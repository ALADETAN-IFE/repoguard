import { getClientIp } from "../src/utils/getClientIp";
import type { Request } from "express";

describe("getClientIp", () => {
  it("prefers Express trusted req.ip when valid", () => {
    const req = {
      ip: "203.0.113.195",
      headers: { "x-forwarded-for": "10.0.0.1, 10.0.0.2" },
    } as unknown as Request;

    expect(getClientIp(req)).toBe("203.0.113.195");
  });

  it("extracts valid IP from x-real-ip when req.ip is not available", () => {
    const req = {
      ip: "",
      headers: { "x-real-ip": "198.51.100.4" },
    } as unknown as Request;

    expect(getClientIp(req)).toBe("198.51.100.4");
  });

  it("extracts first valid IP from x-forwarded-for when req.ip is missing", () => {
    const req = {
      ip: "",
      headers: { "x-forwarded-for": "192.0.2.1, 192.0.2.2" },
    } as unknown as Request;

    expect(getClientIp(req)).toBe("192.0.2.1");
  });

  it("ignores invalid IPs or garbage strings in headers", () => {
    const req = {
      ip: "not-an-ip",
      headers: { "x-real-ip": "malicious<script>", "x-forwarded-for": "garbage, 198.51.100.5" },
    } as unknown as Request;

    expect(getClientIp(req)).toBe("198.51.100.5");
  });

  it("falls back to socket remoteAddress when headers are empty", () => {
    const req = {
      ip: "",
      headers: {},
      socket: { remoteAddress: "127.0.0.1" },
    } as unknown as Request;

    expect(getClientIp(req)).toBe("127.0.0.1");
  });

  it("returns unknown when no valid IP can be identified", () => {
    const req = {
      ip: "",
      headers: {},
      socket: {},
    } as unknown as Request;

    expect(getClientIp(req)).toBe("unknown");
  });
});
