from huc.counters import assess_counters, relative_mismatch
from huc.gpu import parse_gpu_instance_pid
from huc.network import parse_network_event


def test_parse_gpu_instance_pid() -> None:
    assert parse_gpu_instance_pid("pid_1234_luid_0x00000000_0x0000_phys_0_eng_0_engtype_3D") == 1234
    assert parse_gpu_instance_pid("luid_0x1_pid_55_engtype_Copy") == 55
    assert parse_gpu_instance_pid("no_pid_here") is None


def test_parse_network_send_receive() -> None:
    assert parse_network_event(10, {"PID": 123, "size": 4096}) == (123, 4096, True)
    assert parse_network_event(27, {"PID": 321, "size": 2048}) == (321, 2048, False)
    assert parse_network_event(42, {"PID": "7", "size": "100"}) == (7, 100, True)
    assert parse_network_event(999, {"PID": 7, "size": 100}) is None


def test_counter_assessment_ok() -> None:
    result = assess_counters(
        psutil_cpu=25.0,
        windows_cpu=27.0,
        psutil_ram_mb=1000.0,
        windows_ram_mb=990.0,
        gpu_primary=40.0,
        gpu_secondary=42.0,
    )
    assert result.state == "OK"
    assert result.mismatches == 0


def test_counter_assessment_flags_large_disagreement() -> None:
    result = assess_counters(
        psutil_cpu=5.0,
        windows_cpu=90.0,
        psutil_ram_mb=200.0,
        windows_ram_mb=900.0,
        gpu_primary=10.0,
        gpu_secondary=95.0,
        network_events_lost=3,
    )
    assert result.state == "CHECK"
    assert result.mismatches == 4
    assert "CPU disagreement" in result.details
    assert "RAM disagreement" in result.details
    assert "GPU disagreement" in result.details
    assert "ETW lost" in result.details


def test_relative_mismatch_uses_floor_and_ratio() -> None:
    assert not relative_mismatch(10, 18, absolute_floor=15, relative_limit=0.4)
    assert relative_mismatch(10, 80, absolute_floor=15, relative_limit=0.4)
