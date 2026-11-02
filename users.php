<?php
/*
 * pfSense Fleet Manager - user management helper.
 * Sent over SSH on stdin to `/usr/local/bin/php -q`; never stored on the firewall.
 * Mirrors what System > User Manager does when it saves or deletes a user.
 * Needs pfSense CE 2.7+ / Plus 23.05+ (config_get_path API).
 * The fleet server replaces __PAYLOAD__ with base64-encoded JSON.
 */
error_reporting(E_ERROR | E_PARSE);
require_once("config.inc");
require_once("auth.inc");
require_once("functions.inc");

function out($x) { echo "\n@@FLEET-JSON@@" . json_encode($x) . "@@FLEET-END@@\n"; exit(0); }
function fail($m) { out(['error' => $m]); }

if (!function_exists('config_get_path')) {
	fail('User management over SSH needs pfSense CE 2.7 / Plus 23.05 or newer.');
}

/*
 * All logic lives inside fleet_main(): top-level variables in a PHP script are
 * globals, and pfSense keeps its own state in globals such as $g (system paths),
 * $config, $userindex and $groupindex. Clobbering $g breaks write_config().
 */
function groups_of($uid, $groups) {
	$names = [];
	foreach ($groups as $gr) {
		if ($gr['name'] == 'all') continue;
		if (is_array($gr['member']) && in_array($uid, $gr['member'])) $names[] = $gr['name'];
	}
	sort($names);
	return $names;
}

function find_user($users, $name) {
	foreach ($users as $i => $u) {
		if ($u['name'] === $name) return $i;
	}
	return null;
}

function fleet_main() {
	global $userindex, $groupindex;

	$in = json_decode(base64_decode('__PAYLOAD__'), true);
	if (!is_array($in)) {
		fail('Bad request payload');
	}

	$users = config_get_path('system/user', []);
	$groups = config_get_path('system/group', []);

	$op = $in['op'] ?? '';

	if ($op === 'list') {
		$r = [];
		foreach ($users as $u) {
			$r[] = [
				'name' => $u['name'],
				'uid' => (int) $u['uid'],
				'descr' => (string) ($u['descr'] ?? ''),
				'scope' => (string) ($u['scope'] ?? ''),
				'disabled' => isset($u['disabled']),
				'priv' => array_values((array) ($u['priv'] ?? [])),
				'groups' => groups_of($u['uid'], $groups),
				'keys' => base64_decode((string) ($u['authorizedkeys'] ?? '')),
			];
		}
		$gn = [];
		foreach ($groups as $gr) {
			if ($gr['name'] != 'all') $gn[] = $gr['name'];
		}
		out(['users' => $r, 'groups' => $gn]);
	}

	if ($op === 'set') {
		$name = (string) ($in['name'] ?? '');
		if (!preg_match('/^[a-zA-Z0-9._-]{1,32}$/', $name) || $name[0] == '-') {
			fail("Invalid username '{$name}'");
		}
		$idx = find_user($users, $name);
		$new = ($idx === null);
		if ($new && empty($in['password'])) {
			fail("User '{$name}' does not exist here; a password is required to create it.");
		}
		$u = $new ? ['name' => $name, 'scope' => 'user', 'priv' => []] : $users[$idx];

		if (array_key_exists('descr', $in) && $in['descr'] !== null) {
			$u['descr'] = (string) $in['descr'];
		}
		if (array_key_exists('disabled', $in) && $in['disabled'] !== null) {
			if ($in['disabled']) {
				if ((int) ($u['uid'] ?? -1) === 0) fail('The built-in admin account cannot be disabled.');
				$u['disabled'] = true;
			} else {
				unset($u['disabled']);
			}
		}
		if (!empty($in['password'])) {
			unset($u['password'], $u['md5-hash'], $u['sha512-hash'], $u['bcrypt-hash']);
			if (config_get_path('system/webgui/pwhash', 'bcrypt') == 'sha512') {
				$salt = substr(bin2hex(random_bytes(16)), 0, 16);
				$u['sha512-hash'] = crypt($in['password'], '$6$' . $salt . '$');
			} else {
				$u['bcrypt-hash'] = password_hash($in['password'], PASSWORD_BCRYPT);
			}
		}
		if (array_key_exists('keys', $in) && $in['keys'] !== null) {
			$u['authorizedkeys'] = base64_encode((string) $in['keys']);
		}
		if (array_key_exists('shell', $in) && $in['shell'] !== null) {
			$p = array_values(array_diff((array) ($u['priv'] ?? []), ['user-shell-access']));
			if ($in['shell']) $p[] = 'user-shell-access';
			$u['priv'] = $p;
		}

		if ($new) {
			$next = (int) config_get_path('system/nextuid');
			$u['uid'] = $next;
			config_set_path('system/nextuid', $next + 1);
			/* every user belongs to the "all" group, as in the GUI */
			foreach ($groups as &$grp) {
				if ($grp['name'] == 'all') {
					if (!is_array($grp['member'])) $grp['member'] = [];
					$grp['member'][] = $u['uid'];
					break;
				}
			}
			unset($grp);
			config_set_path('system/group', $groups);
			$users[] = $u;
		} else {
			$users[$idx] = $u;
		}
		usort($users, function ($a, $b) { return strcmp($a['name'], $b['name']); });
		config_set_path('system/user', $users);

		$userindex = index_users();
		$groupindex = index_groups();

		if (array_key_exists('groups', $in) && is_array($in['groups'])) {
			$known = [];
			foreach (config_get_path('system/group', []) as $grp) $known[] = $grp['name'];
			$missing = array_diff($in['groups'], $known);
			if ($missing) fail('Unknown group(s): ' . implode(', ', $missing));
			$want = array_values(array_unique(array_merge($in['groups'], ['all'])));
			local_user_set_groups($u, $want);
		}
		local_user_set($u);
		$userindex = index_users();

		$msg = 'Fleet manager: ' . ($new ? 'created' : 'updated') . " user {$name}";
		write_config($msg);
		out(['ok' => true, 'text' => ($new ? 'Created' : 'Updated') . " user {$name}"]);
	}

	if ($op === 'delete') {
		$name = (string) ($in['name'] ?? '');
		$idx = find_user($users, $name);
		if ($idx === null) {
			out(['ok' => true, 'text' => "User {$name} not present (nothing to do)"]);
		}
		$u = $users[$idx];
		if ((int) $u['uid'] === 0 || ($u['scope'] ?? '') === 'system') {
			fail("{$name} is a built-in account and cannot be deleted.");
		}
		local_user_del($u);
		config_del_path("system/user/{$idx}");
		config_set_path('system/user', array_values(config_get_path('system/user', [])));
		write_config("Fleet manager: deleted user {$name}");
		out(['ok' => true, 'text' => "Deleted user {$name}"]);
	}

	fail("Unknown operation '{$op}'");
}

fleet_main();
