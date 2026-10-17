import { useEffect, useRef } from "react";
import { interpolateRdYlGn, scaleBand, scaleSequential, select } from "d3";
import type { demoFairnessCells } from "../data/demoTelemetry";

type HeatCell = (typeof demoFairnessCells)[number];

export function FairnessHeatmap({ data }: { data: HeatCell[] }) {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!host.current) return;
    const hostSelection = select(host.current);
    hostSelection.selectAll("*").remove();

    const groups = [...new Set(data.map(cell => cell.group))];
    const metrics = [...new Set(data.map(cell => cell.metric))];
    const width = 520;
    const height = 190;
    const margin = { top: 18, right: 12, bottom: 12, left: 116 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;
    const x = scaleBand<string>().domain(metrics).range([0, innerWidth]).padding(0.09);
    const y = scaleBand<string>().domain(groups).range([0, innerHeight]).padding(0.12);
    const color = scaleSequential(interpolateRdYlGn).domain([0.60, 0.95]);

    const svg = hostSelection
      .append("svg")
      .attr("viewBox", `0 0 ${width} ${height}`)
      .attr("role", "img")
      .attr("aria-label", "Demonstration fairness metric heatmap by synthetic group");

    const chart = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);
    chart.selectAll(".metric-label")
      .data(metrics)
      .join("text")
      .attr("x", metric => (x(metric) ?? 0) + (x.bandwidth() / 2))
      .attr("y", -5)
      .attr("text-anchor", "middle")
      .attr("class", "heatmap-axis-label")
      .text(metric => metric);

    chart.selectAll(".group-label")
      .data(groups)
      .join("text")
      .attr("x", -10)
      .attr("y", group => (y(group) ?? 0) + y.bandwidth() / 2 + 4)
      .attr("text-anchor", "end")
      .attr("class", "heatmap-axis-label")
      .text(group => group);

    chart.selectAll(".heatmap-cell")
      .data(data)
      .join("rect")
      .attr("class", "heatmap-cell")
      .attr("x", cell => x(cell.metric) ?? 0)
      .attr("y", cell => y(cell.group) ?? 0)
      .attr("width", x.bandwidth())
      .attr("height", y.bandwidth())
      .attr("rx", 4)
      .attr("fill", cell => color(cell.score))
      .append("title")
      .text(cell => `${cell.group} · ${cell.metric}: ${(cell.score * 100).toFixed(0)}% (synthetic)`);

    chart.selectAll(".heatmap-value")
      .data(data)
      .join("text")
      .attr("x", cell => (x(cell.metric) ?? 0) + x.bandwidth() / 2)
      .attr("y", cell => (y(cell.group) ?? 0) + y.bandwidth() / 2 + 4)
      .attr("text-anchor", "middle")
      .attr("class", "heatmap-value")
      .text(cell => `${(cell.score * 100).toFixed(0)}%`);
  }, [data]);

  return <div className="heatmap-scroll" ref={host} />;
}
