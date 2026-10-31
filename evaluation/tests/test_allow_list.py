"""
tests for the narrow allow-list of the scenario lint and for the new scenario fields (group, needs, locations); every script and scenario written here is a !!constructed fixture!!
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(HERE)
sys.path.insert(0, EVAL_DIR)
sys.path.insert(0, HERE)

import scenario_lib as lib  #noqa: E402
from test_scenarios import directory  #noqa: E402

ALL = ("tmp", "shm", "cron", "systemd", "home")


def lint(text, locations=ALL, **kw):
    return lib.lint_script(text, locations=locations, **kw)


class Cron(unittest.TestCase):

    def test_accepted_forms(self):
        for text in ['echo "# x" > "$EVT_EVAL_CRON_FILE"', "echo x > /etc/cron.d/evt_eval_s18", 'echo x > "$EVT_EVAL_CRON_DIR/evt_eval_s18"',
                     'mv "$EVT_EVAL_WORK/a.cron" /etc/cron.d/evt_eval_x', 'mv "$EVT_EVAL_WORK/a.cron" "$EVT_EVAL_CRON_FILE"',
                     'rm -f "$EVT_EVAL_CRON_FILE"', "rm -f /etc/cron.d/evt_eval_x", 'cp "$EVT_EVAL_WORK/a" "$EVT_EVAL_CRON_FILE"']:
            self.assertEqual(lint(text), [], text)

    def test_rejected_forms(self):
        for text in ['mv "$EVT_EVAL_WORK/a" /etc/cron.daily/evt_eval_x', 'mv "$EVT_EVAL_WORK/a" /etc/cron.d/other',
                     "echo x > /etc/cron.d/../passwd", "echo x > /etc/cron.d/evt_eval_x/../y", "echo x > /etc/cron.d/evt_eval_*",
                     "echo x > /etc/cron.d/evt_eval_X", "echo x > /etc/cron.hourly/evt_eval_x", "echo x > /etc/crontab", "touch /etc/cron.d/",
                     "echo x > /etc/cron.d/evt_eval_x/sub"]:
            self.assertTrue(lint(text), text)

    def test_the_location_has_to_be_declared(self):
        self.assertTrue(lint("echo x > /etc/cron.d/evt_eval_x", locations=()))
        self.assertTrue(lint('echo x > "$EVT_EVAL_CRON_FILE"', locations=("systemd",)))
        self.assertIn("uses cron without declaring it", [r for _, r in lint('echo x > "$EVT_EVAL_CRON_FILE"', locations=())])


class Systemd(unittest.TestCase):

    def test_accepted_and_rejected(self):
        for text in ["printf x > /etc/systemd/system/evt_eval_s21.service", 'printf x > "$EVT_EVAL_UNIT"', 'rm -f "$EVT_EVAL_UNIT"',
                     'printf x > "$EVT_EVAL_SYSTEMD_DIR/evt_eval_s21.service"']:
            self.assertEqual(lint(text), [], text)
        for text in ["printf x > /etc/systemd/system/other.service", "printf x > /etc/systemd/system/evt_eval_x", "printf x > /etc/systemd/system/evt_eval_x.service.d/a",
                     "printf x > /etc/systemd/system/evt_eval_x.service/../y", "printf x > /etc/systemd/system/multi-user.target.wants/evt_eval_x.service",
                     "printf x > /usr/lib/systemd/system/evt_eval_x.service", "systemctl enable evt_eval_x"]:
            self.assertTrue(lint(text), text)


class Shm(unittest.TestCase):

    def test_accepted_and_rejected(self):
        for text in ["mkdir -p /dev/shm/evt_eval_s12", 'cp /bin/true "$EVT_EVAL_SHM/true"', 'rm -rf "$EVT_EVAL_SHM"', "touch /dev/shm/evt_eval_x/f",
                     'mkdir -p "$EVT_EVAL_SHM_BASE/evt_eval_s12"']:
            self.assertEqual(lint(text), [], text)
        for text in ["touch /dev/shm/other", "touch /dev/shm/evt_eval_x/../y", "rm -rf /dev/shm", "touch /dev/shm/evt_eval_*", "rm -rf /dev/shm/evt_eval_x/.."]:
            self.assertTrue(lint(text), text)


class Home(unittest.TestCase):

    def test_accepted_and_rejected(self):
        for text in ["mkdir -p /home/evt_eval_s19/.ssh", 'echo x >> "$EVT_EVAL_HOME/.bashrc"', 'rm -rf "$EVT_EVAL_HOME"', 'mkdir -p "$EVT_EVAL_HOME/.ssh"',
                     'echo x > "$EVT_EVAL_HOME_BASE/evt_eval_s19/.bashrc"', "chmod 600 /home/evt_eval_s15/.ssh/id_ed25519"]:
            self.assertEqual(lint(text), [], text)
        for text in ["echo x > /home/bob/.bashrc", "mkdir /home/evt_other/x", "echo x > /home/evt_eval_x/../bob/.bashrc", "mkdir /home/evt_eval_X",
                     "echo x > /home/evt_eval_*/.bashrc", "echo x > /root/.bashrc", "echo x > /home", "rm -rf /home/evt_eval_x/.."]:
            self.assertTrue(lint(text), text)

    def test_a_read_of_a_home_path_also_needs_the_declaration(self):
        self.assertTrue(lint("ls /home/evt_eval_x", locations=()))
        self.assertEqual(lint("ls /home/evt_eval_x", locations=("home",)), [])


class NeverAllowed(unittest.TestCase):

    def test_account_and_sudoers_files_and_the_preload_file(self):
        for text in ["echo x > /etc/passwd", "echo x >> /etc/shadow", "echo x > /etc/sudoers.d/evt_eval_x", "tee /etc/sudoers", "echo x > /etc/ld.so.preload",
                     "cp a /etc/passwd", "mv a /etc/shadow"]:
            self.assertTrue(lint(text), text)

    def test_the_other_denied_commands_stay_denied_with_every_location_declared(self):
        for text in ["systemctl status x", "crontab -l", "mkfs.ext4 /dev/x", "dd if=/dev/zero of=/dev/sda", "shutdown now", "reboot", "iptables -L",
                     "rm -rf /opt/other", 'rm -rf "$OTHER"', "rm -rf /home/evt_eval_x/.."]:
            self.assertTrue(lint(text), text)


class Impersonation(unittest.TestCase):

    def test_sudo_su_pkexec_doas_are_rejected_as_commands(self):
        for text in ["sudo ls", "su root", "pkexec id", "doas id", "echo a; sudo id", "env sudo id", "bash -c 'sudo id'", "xargs su", "(sudo id)", "a | sudo tee x"]:
            self.assertTrue(lint(text), text)

    def test_a_copy_made_under_the_work_directory_may_be_executed_by_its_explicit_path(self):
        for name in ("sudo", "su", "pkexec", "doas", "crontab", "systemctl"):
            made = 'cp /bin/cat "$EVT_EVAL_WORK/%s"\n"$EVT_EVAL_WORK/%s" /etc/shadow > /dev/null\n' % (name, name)
            self.assertEqual(lint(made), [], name)
            linked = 'ln -s /usr/bin/python3 "$EVT_EVAL_WORK/%s"\n"$EVT_EVAL_WORK/%s" x.py\n' % (name, name)
            self.assertEqual(lint(linked), [], name)

    def test_a_copy_that_was_not_made_in_the_script_is_not_accepted(self):
        self.assertTrue(lint('"$EVT_EVAL_WORK/sudo" /etc/shadow'))
        self.assertTrue(lint('cp /bin/cat "$EVT_EVAL_WORK/other"\n"$EVT_EVAL_WORK/sudo" /etc/shadow'))

    def test_the_explicit_path_has_to_be_under_the_work_directory(self):
        self.assertTrue(lint('cp /bin/cat "$EVT_EVAL_WORK/sudo"\n/usr/bin/sudo id'))
        self.assertTrue(lint('cp /bin/cat "$EVT_EVAL_WORK/sudo"\n./sudo id'))
        self.assertTrue(lint('cp /bin/cat "$EVT_EVAL_WORK/sudo"\n"$EVT_EVAL_HOME/sudo" id'))
        self.assertTrue(lint('cp /bin/cat /usr/bin/sudo'))
        self.assertTrue(lint('cp /bin/cat "$EVT_EVAL_WORK/sudo"\n"$EVT_EVAL_WORK/sub/sudo" id'))

    def test_the_lint_is_token_aware(self):
        for text in ["echo pseudo", "ls sudoers", "echo suspicious", "cat visudo.txt", "echo halted", "echo rebooted", "ls resume"]:
            self.assertEqual(lint(text), [], text)

    def test_a_copy_created_in_another_script_of_the_scenario_counts(self):
        self.assertTrue(lint('"$EVT_EVAL_WORK/sudo" x'))
        self.assertEqual(lint('"$EVT_EVAL_WORK/sudo" x', created={"sudo"}), [])


class Fields(unittest.TestCase):

    def test_group_is_checked(self):
        d = directory(self)
        d.add("T1", {"group": None})
        d.add("T2", {"group": "other"})
        d.add("T3", {"kind": "benign", "technique": None, "expected": [], "group": "gap"})
        d.add("T4", {"kind": "benign", "technique": None, "expected": [], "group": None})
        d.add("T5", drop=("group",))
        text = " ".join(d.problems())
        self.assertIn("T1: group of an attack must be ordinary or gap", text)
        self.assertIn("T2: group of an attack must be ordinary or gap", text)
        self.assertIn("T3: a benign scenario has group null", text)
        self.assertNotIn("T4:", text)
        self.assertIn("T5: missing fields ['group']", text)

    def test_needs_and_locations_are_checked(self):
        d = directory(self)
        d.add("T1", {"needs": ["a_gpu"]})
        d.add("T2", {"locations": ["etc"]})
        d.add("T3", {"needs": ["non_loopback_ipv4"], "locations": ["cron", "home"]})
        text = " ".join(d.problems())
        self.assertIn("T1: needs must be a list of non_loopback_ipv4", text)
        self.assertIn("T2: locations must be a list of", text)
        self.assertNotIn("T3:", text)

    def test_a_script_that_touches_an_undeclared_location_is_rejected(self):
        d = directory(self)
        d.add("T1", action='echo x > "$EVT_EVAL_CRON_FILE"\n')
        d.add("T2", {"locations": ["cron"]}, action='echo x > "$EVT_EVAL_CRON_FILE"\n')
        d.add("T3", {"locations": ["home"]}, action='echo x > "$EVT_EVAL_CRON_FILE"\n')
        text = " ".join(d.problems())
        self.assertIn("T1: unsafe script action.sh line 1: uses cron without declaring it", text)
        self.assertNotIn("T2:", text)
        self.assertIn("T3: unsafe script action.sh line 1", text)

    def test_the_address_variable_needs_the_declared_need(self):
        d = directory(self)
        d.add("T1", action='echo "$EVT_EVAL_NONLOOPBACK_IPV4"\n')
        d.add("T2", {"needs": ["non_loopback_ipv4"]}, action='echo "$EVT_EVAL_NONLOOPBACK_IPV4"\n')
        text = " ".join(d.problems())
        self.assertIn("T1: action.sh uses the non-loopback address without declaring the need", text)
        self.assertNotIn("T2:", text)

    def test_tmp_staging_still_declares_tmp(self):
        d = directory(self)
        d.add("T1", {"tmp_staging": True}, setup='mkdir -p "$EVT_EVAL_TMP"\n')
        self.assertEqual(d.problems(), [])

    def test_the_environment_has_the_new_variables(self):
        env = lib.scenario_env("S18_Write", address="10.0.0.5")
        self.assertEqual(env["EVT_EVAL_CRON_FILE"], "/etc/cron.d/evt_eval_s18_write")
        self.assertEqual(env["EVT_EVAL_UNIT"], "/etc/systemd/system/evt_eval_s18_write.service")
        self.assertEqual(env["EVT_EVAL_HOME"], "/home/evt_eval_s18")
        self.assertEqual(env["EVT_EVAL_SHM"], "/dev/shm/evt_eval_s18_write")
        self.assertEqual((env["EVT_EVAL_CRON_DIR"], env["EVT_EVAL_SYSTEMD_DIR"], env["EVT_EVAL_HOME_BASE"], env["EVT_EVAL_SHM_BASE"]),
                         ("/etc/cron.d", "/etc/systemd/system", "/home", "/dev/shm"))
        self.assertEqual(env["EVT_EVAL_NONLOOPBACK_IPV4"], "10.0.0.5")
        self.assertNotIn("EVT_EVAL_NONLOOPBACK_IPV4", lib.scenario_env("S18_Write"))
        scratch = lib.scenario_env("S18_Write", bases={"cron": "/scratch/c", "work": "/scratch/w"})
        self.assertEqual((scratch["EVT_EVAL_CRON_FILE"], scratch["EVT_EVAL_WORK"]), ("/scratch/c/evt_eval_s18_write", "/scratch/w/evt_eval_s18_write"))
        self.assertEqual(len(lib.scenario_paths("S18_Write")), 6)


if __name__ == "__main__":
    unittest.main()
