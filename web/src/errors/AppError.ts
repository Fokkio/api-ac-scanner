export class AppError extends Error {
  public constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode: number,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

export class ValidationError extends AppError {
  public constructor(message: string) {
    super("VALIDATION_ERROR", message, 400);
  }
}

export class ForbiddenError extends AppError {
  public constructor(message = "You are not allowed to perform this action") {
    super("FORBIDDEN", message, 403);
  }
}

export class RequestTooLargeError extends AppError {
  public constructor(message = "The request exceeded the configured size limit") {
    super("REQUEST_TOO_LARGE", message, 413);
  }
}

export class NotFoundError extends AppError {
  public constructor(message: string) {
    super("NOT_FOUND", message, 404);
  }
}

export class CapacityError extends AppError {
  public constructor() {
    super("QUEUE_FULL", "The scanner is busy. Try again later.", 429);
  }
}

export class UpstreamError extends AppError {
  public constructor(message: string) {
    super("SCANNER_UNAVAILABLE", message, 502);
  }
}
