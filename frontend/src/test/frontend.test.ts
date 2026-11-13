import { describe, expect, it } from "vitest";
import {
  formatTime,
  severityClass,
  severityLabel,
  statusClass,
  timeAgo,
  truncate,
} from "../lib/format";
import { canAct } from "../store/auth";

describe("format helpers", () => {
  it("maps OCSF severity ids to labels", () => {
    expect(severityLabel(4)).toBe("High");
    expect(severityLabel(5)).toBe("Critical");
    expect(severityLabel(9)).toBe("Unknown(9)");
  });

  it("colors critical severities red and low severities cyan", () => {
    expect(severityClass(5)).toContain("red");
    expect(severityClass(2)).toContain("cyan");
  });

  it("formats relative times", () => {
    expect(timeAgo(new Date(Date.now() - 5_000).toISOString())).toBe("5s ago");
    expect(timeAgo(null)).toBe("—");
  });

  it("formats absolute times without throwing on junk", () => {
    expect(formatTime("not-a-date")).toBe("not-a-date");
    expect(formatTime(null)).toBe("—");
  });

  it("truncates long strings", () => {
    expect(truncate("abcdef", 4)).toBe("abc…");
    expect(truncate("ab", 4)).toBe("ab");
  });

  it("colors workflow statuses", () => {
    expect(statusClass("open")).toContain("red");
    expect(statusClass("resolved")).toContain("emerald");
  });
});

describe("RBAC helper", () => {
  it("ranks roles correctly", () => {
    expect(canAct("admin", "analyst")).toBe(true);
    expect(canAct("viewer", "analyst")).toBe(false);
    expect(canAct("analyst", "analyst")).toBe(true);
    expect(canAct(undefined, "viewer")).toBe(false);
  });
});