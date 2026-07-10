from pathlib import Path
import unittest

from app.analyzer import analyze_entries
from app.log_reader import parse_log_line
from app.rules_engine import RuleSet


ROOT = Path(__file__).resolve().parents[1]


class RouterAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = RuleSet.load(ROOT / "rules.yaml")

    def entry(self, timestamp: str, message: str) -> dict[str, object]:
        return parse_log_line(
            f"{timestamp} GT-AX6000-09D8-F809252-C {message}",
            "remote/GT-AX6000-09D8-F809252-C/2026-07-10.log",
            path_device="GT-AX6000-09D8-F809252-C",
            rules=self.rules,
        )

    def test_service_watchdog_is_not_device_reboot(self) -> None:
        entry = self.entry(
            "2026-07-10T06:00:14+08:00",
            'rc_service: watchdog 3510:notify_rc stop_aae',
        )

        self.assertIn("router_service_watchdog_loop", entry["categories"])
        self.assertNotIn("watchdog", entry["categories"])
        self.assertNotIn("reboot", entry["categories"])

    def test_web_reboot_request_is_not_completed_reboot(self) -> None:
        entry = self.entry(
            "2026-07-10T00:29:35+08:00",
            "rc_service: httpd 3507:notify_rc reboot",
        )

        self.assertIn("router_reboot_request", entry["categories"])
        self.assertNotIn("reboot", entry["categories"])

    def test_router_ssh_scan_does_not_use_nas_category(self) -> None:
        entry = self.entry(
            "2026-07-10T07:25:12+08:00",
            "dropbear[23093]: Exit before auth from <195.178.110.137:52568>: Exited normally",
        )

        self.assertIn("auth_failed", entry["categories"])
        self.assertNotIn("nas_login_failed", entry["categories"])

    def test_repeated_mastiff_restart_has_specific_problem(self) -> None:
        entries = []
        for index in range(6):
            entries.append(
                self.entry(
                    f"2026-07-10T06:0{index}:14+08:00",
                    'rc_service: watchdog 3510:notify_rc start_mastiff',
                )
            )

        problems = analyze_entries(entries)
        titles = [str(problem["title"]) for problem in problems]

        self.assertIn("ASUS mastiff/aae 服务重启风暴", titles)
        self.assertNotIn("设备疑似异常重启", titles)

    def test_broadcom_ipv6_crash_path_is_identified(self) -> None:
        entries = [
            self.entry(
                "2026-07-10T00:43:01+08:00",
                "router-crash-collector: UNCLEAN_BOOT suspected=true previous_state=running-old",
            ),
            self.entry(
                "2026-07-10T00:43:02+08:00",
                "router-crash-collector: CRASHLOG Unable to handle kernel NULL pointer dereference",
            ),
            self.entry(
                "2026-07-10T00:43:03+08:00",
                "router-crash-collector: CRASHLOG Call trace: bcm_tcp_v4_recv tcp_v6_syn_recv_sock inet6_sk_rx_dst_set",
            ),
            self.entry(
                "2026-07-10T00:43:04+08:00",
                "router-crash-collector: CRASHLOG Kernel panic - not syncing: Fatal exception in interrupt",
            ),
        ]

        problems = analyze_entries(entries)
        titles = [str(problem["title"]) for problem in problems]

        self.assertIn("路由器疑似非正常重启", titles)
        self.assertIn("Broadcom IPv6 网络路径内核崩溃", titles)

    def test_historical_soft_lockup_is_not_counted_as_reboot(self) -> None:
        entries = [
            self.entry(
                "2026-07-10T07:51:12+08:00",
                "router-crash-collector: CRASHLOG watchdog: BUG: soft lockup - CPU#0 stuck for 23s!",
            ),
            self.entry(
                "2026-07-10T07:51:13+08:00",
                "router-crash-collector: CRASHLOG watchdog: BUG: soft lockup - CPU#3 stuck for 23s!",
            ),
        ]

        problems = analyze_entries(entries)
        titles = [str(problem["title"]) for problem in problems]

        self.assertIn("路由器 CPU soft lockup", titles)
        self.assertNotIn("设备疑似异常重启", titles)

    def test_crashlog_storage_error_has_solution_template(self) -> None:
        entry = self.entry(
            "2026-07-10T07:39:18+08:00",
            "kernel: Buffer I/O error on dev mtdblock3, logical block 0, async page read",
        )

        problems = analyze_entries([entry])

        self.assertEqual(problems[0]["title"], "路由器 crashlog 分区读取异常")
        self.assertTrue(problems[0]["suggested_steps"])


if __name__ == "__main__":
    unittest.main()
