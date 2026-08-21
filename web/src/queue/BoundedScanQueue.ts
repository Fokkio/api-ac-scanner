import { CapacityError } from "../errors/AppError";

export interface ScanQueueJob {
  scanId: string;
  run: () => Promise<void>;
}

/** Bounded, single-process queue that prevents unbounded scan concurrency. */
export class BoundedScanQueue {
  private readonly pendingJobs: ScanQueueJob[] = [];
  private activeJobs = 0;

  public constructor(
    private readonly concurrency: number,
    private readonly capacity: number,
  ) {}

  /** Enqueues a scan or throws when the bounded queue is full. */
  public enqueue(job: ScanQueueJob): void {
    if (this.activeJobs + this.pendingJobs.length >= this.capacity) throw new CapacityError();
    this.pendingJobs.push(job);
    this.drain();
  }

  /** Returns current queue counters for health and tests. */
  public getStats(): { active: number; pending: number; capacity: number } {
    return { active: this.activeJobs, pending: this.pendingJobs.length, capacity: this.capacity };
  }

  private drain(): void {
    while (this.activeJobs < this.concurrency && this.pendingJobs.length > 0) {
      const job = this.pendingJobs.shift();
      if (!job) return;
      this.activeJobs += 1;
      void this.execute(job);
    }
  }

  private async execute(job: ScanQueueJob): Promise<void> {
    try {
      await job.run();
    } catch (error: unknown) {
      console.error("Unexpected queue job failure", { scanId: job.scanId, error });
    } finally {
      this.activeJobs -= 1;
      this.drain();
    }
  }
}
