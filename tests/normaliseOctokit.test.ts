import { normaliseOctokit } from "../src/utils/normaliseOctokit";

describe("normaliseOctokit", () => {
  it("should return the client as-is if it is a flat Octokit instance", () => {
    const flatClient = { request: jest.fn() };
    const result = normaliseOctokit(flatClient);
    expect(result).toBe(flatClient);
  });

  it("should extract and return the nested octokit property if present", () => {
    const nestedClient = { request: jest.fn() };
    const wrapper = { octokit: nestedClient };
    const result = normaliseOctokit(wrapper);
    expect(result).toBe(nestedClient);
  });

  it("should return null or undefined as-is", () => {
    expect(normaliseOctokit(undefined)).toBeUndefined();
    expect(normaliseOctokit(null)).toBeNull();
  });
});
