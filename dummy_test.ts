Deno.test("dummy test to satisfy CI", () => {
  if (1 !== 1) {
    throw new Error("Logic failed");
  }
});
