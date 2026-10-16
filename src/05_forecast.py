"""Holt-Winters baseline on hourly failed logins; flag hours far outside the expected band."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from statsmodels.tsa.holtwinters import ExponentialSmoothing

import config
from plots import style


def main():
    df = pd.read_csv(config.OUT / "hourly.csv", parse_dates=["hour"]).set_index("hour").asfreq("h", fill_value=0)
    y = df["failed"].astype(float)
    # log1p keeps huge attack bursts from dominating the seasonal fit
    model = ExponentialSmoothing(np.log1p(y), trend="add", seasonal="add", seasonal_periods=24,
                                 initialization_method="estimated").fit()
    fitted = np.expm1(model.fittedvalues).clip(lower=0)
    resid = np.log1p(y) - model.fittedvalues
    band = 3 * resid.std()
    upper = np.expm1(model.fittedvalues + band)
    out = pd.DataFrame({"failed": y, "expected": fitted.round(1), "upper_band": upper.round(1)})
    out["anomaly"] = y > out["upper_band"]
    future = np.expm1(model.forecast(24)).clip(lower=0)
    out.to_csv(config.OUT / "hourly_forecast.csv")
    future.rename("forecast").rename_axis("hour").to_csv(config.OUT / "next_24h_forecast.csv")

    fig, ax = plt.subplots(figsize=(11, 4.2))
    ax.fill_between(out.index, 0, out["upper_band"], color="#cde2fb", label="Expected band (+3σ)")
    ax.plot(out.index, out["failed"], color=config.MUTED, linewidth=1, label="Failed logins")
    ax.plot(out.index, out["expected"], color=config.COLORS[0], linewidth=1.6, label="Holt-Winters baseline")
    ax.plot(future.index, future, color=config.COLORS[0], linewidth=1.6, linestyle="--", label="Next 24h forecast")
    a = out[out["anomaly"]]
    ax.scatter(a.index, a["failed"], s=36, color=config.COLORS[7], edgecolors="white", linewidths=0.8,
               zorder=3, label=f"Anomalous hour ({len(a)})")
    ax.set_yscale("symlog", linthresh=10)
    style(ax, "Hourly failed SSH logins against a Holt-Winters baseline", ylabel="Failed logins / hour (symlog)")
    ax.legend(frameon=False, fontsize=8, ncol=3, loc="upper left")
    config.FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(config.FIG / "forecast_anomalies.png", dpi=150, bbox_inches="tight")
    print(f"{len(a)} anomalous hours of {len(out)}; top 10:")
    print(a.sort_values("failed", ascending=False).head(10).to_string())


if __name__ == "__main__":
    main()
