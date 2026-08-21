import "express-session";

declare module "express-session" {
  interface SessionData {
    isAuthenticated?: boolean;
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
