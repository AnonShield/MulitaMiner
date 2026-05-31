"""
Background sampler for per-run GPU metrics via `nvidia-smi`.

While a run executes, polls memory.used, power.draw and utilization, then
reports peak VRAM, integrated GPU energy (Wh) and utilization stats. No-ops
gracefully when `nvidia-smi` is unavailable (cloud runs, non-NVIDIA hosts).

Note: the numbers reflect the WHOLE GPU during the run window (the model plus
anything else on the card) and energy is the GPU board only — not CPU/system.
"""

import subprocess
import threading
import time


class GpuSampler:
    def __init__(self, gpu_index: int = 0, interval: float = 0.5):
        self.gpu_index = gpu_index
        self.interval = interval
        self._thread = None
        self._stop = threading.Event()
        self._samples = []  # (timestamp, mem_mb, power_w, util_pct)
        self._available = self._check_available()

    def _check_available(self) -> bool:
        try:
            subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.used",
                 "--format=csv,noheader,nounits", "-i", str(self.gpu_index)],
                capture_output=True, text=True, timeout=5, check=True,
            )
            return True
        except Exception:
            return False

    def _poll_once(self):
        out = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=memory.used,power.draw,utilization.gpu",
             "--format=csv,noheader,nounits", "-i", str(self.gpu_index)],
            capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip()
        mem, power, util = [p.strip() for p in out.split(",")]
        return float(mem), float(power), float(util)

    def _run(self):
        while not self._stop.is_set():
            try:
                mem, power, util = self._poll_once()
                self._samples.append((time.time(), mem, power, util))
            except Exception:
                pass
            self._stop.wait(self.interval)

    def start(self) -> "GpuSampler":
        if not self._available:
            return self
        self._stop.clear()
        self._samples = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> dict:
        """Stop sampling and return the summary dict."""
        if not self._available or self._thread is None:
            return {"gpu_metrics_available": False}
        self._stop.set()
        self._thread.join(timeout=5)
        return self._summarize()

    def _summarize(self) -> dict:
        if not self._samples:
            return {"gpu_metrics_available": False}

        mems = [s[1] for s in self._samples]
        utils = [s[3] for s in self._samples]

        # Integrate power over time (trapezoidal) -> Joules -> Wh
        energy_j = 0.0
        for (t0, _, p0, _), (t1, _, p1, _) in zip(self._samples, self._samples[1:]):
            energy_j += (p0 + p1) / 2.0 * (t1 - t0)

        return {
            "gpu_metrics_available": True,
            "peak_vram_mb": round(max(mems), 1),
            "gpu_energy_wh": round(energy_j / 3600.0, 4),
            "gpu_util_avg": round(sum(utils) / len(utils), 1),
            "gpu_util_max": round(max(utils), 1),
            "gpu_samples": len(self._samples),
        }
