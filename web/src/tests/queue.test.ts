import assert from "node:assert/strict";
import test from "node:test";
import { CapacityError } from "../errors/AppError";
import { BoundedScanQueue } from "../queue/BoundedScanQueue";

test("enforces total active plus pending capacity", async () => {
  let releaseFirst: (() => void) | undefined;
  const firstJob = new Promise<void>((resolve) => { releaseFirst = resolve; });
  const queue = new BoundedScanQueue(1, 2);

  queue.enqueue({ scanId: "one", run: () => firstJob });
  queue.enqueue({ scanId: "two", run: async () => undefined });
  assert.deepEqual(queue.getStats(), { active: 1, pending: 1, capacity: 2 });
  assert.throws(
    () => queue.enqueue({ scanId: "three", run: async () => undefined }),
    CapacityError,
  );

  releaseFirst?.();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(queue.getStats(), { active: 0, pending: 0, capacity: 2 });
});
