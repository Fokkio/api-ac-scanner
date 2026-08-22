import "express-session";

declare module "express-session" {
  interface SessionData {
    csrfToken?: string;
  }
}

declare global {
  namespace Express {
    interface Request {
      uploadDirectory?: string;
    }
  }
}

export {};
