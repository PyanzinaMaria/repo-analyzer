// Renders any element carrying a JSON ECharts option in data-option.
// Generic: works for the donut summary and any future chart partials.
// Re-runs after HTMX swaps because polled fragments may contain new charts.
(function () {
    function initCharts() {
        if (typeof echarts === "undefined") return;
        for (const el of document.querySelectorAll("[data-option]:not([data-chart-init])")) {
            el.dataset.chartInit = "1";
            echarts.init(el).setOption(JSON.parse(el.dataset.option));
        }
    }
    document.addEventListener("DOMContentLoaded", initCharts);
    document.body.addEventListener("htmx:afterSwap", initCharts);
})();
