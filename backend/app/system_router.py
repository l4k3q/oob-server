from __future__ import annotations
import os
import time

from fastapi import APIRouter, Depends

from .auth.deps import current_user as get_current_user

router = APIRouter(prefix="/api/system", tags=["system"])


def _read_proc_stat() -> dict:
    """Parse /proc/stat for CPU usage (Linux only)."""
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        fields = list(map(int, line.split()[1:]))
        idle = fields[3]
        total = sum(fields)
        return {"idle": idle, "total": total}
    except Exception:
        return {}


def _cpu_percent() -> float:
    """Approximate CPU usage by sampling /proc/stat twice."""
    try:
        import psutil
        return round(psutil.cpu_percent(interval=0.2), 1)
    except ImportError:
        pass
    try:
        s1 = _read_proc_stat()
        time.sleep(0.2)
        s2 = _read_proc_stat()
        if not s1 or not s2:
            return -1.0
        idle_diff  = s2["idle"]  - s1["idle"]
        total_diff = s2["total"] - s1["total"]
        return round((1 - idle_diff / total_diff) * 100, 1) if total_diff else -1.0
    except Exception:
        return -1.0


def _mem_info() -> dict:
    try:
        import psutil
        m = psutil.virtual_memory()
        return {"total_mb": m.total // 1024**2, "used_mb": m.used // 1024**2,
                "percent": round(m.percent, 1)}
    except ImportError:
        pass
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":")
                info[k.strip()] = int(v.split()[0])
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        used  = total - avail
        return {"total_mb": total // 1024, "used_mb": used // 1024,
                "percent": round(used / total * 100, 1) if total else 0}
    except Exception:
        return {}


def _disk_info(path: str = "/") -> dict:
    try:
        import psutil
        d = psutil.disk_usage(path)
        return {"total_gb": round(d.total / 1024**3, 1), "used_gb": round(d.used / 1024**3, 1),
                "percent": round(d.percent, 1)}
    except ImportError:
        pass
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        free  = st.f_bfree  * st.f_frsize
        used  = total - free
        return {"total_gb": round(total / 1024**3, 1), "used_gb": round(used / 1024**3, 1),
                "percent": round(used / total * 100, 1) if total else 0}
    except Exception:
        return {}


@router.get("/info")
async def system_info(_: str = Depends(get_current_user)):
    """Return server resource usage for the dashboard."""
    return {
        "cpu_percent": _cpu_percent(),
        "mem":  _mem_info(),
        "disk": _disk_info(),
        "uptime_s": int(time.time() - _boot_time()),
        "load_avg": _load_avg(),
    }


def _boot_time() -> float:
    try:
        import psutil
        return psutil.boot_time()
    except ImportError:
        pass
    try:
        with open("/proc/uptime") as f:
            up_secs = float(f.read().split()[0])
        return time.time() - up_secs
    except Exception:
        return time.time()


def _load_avg() -> list[float]:
    try:
        la = os.getloadavg()
        return [round(x, 2) for x in la]
    except Exception:
        return []
