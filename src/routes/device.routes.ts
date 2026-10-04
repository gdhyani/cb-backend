import { Router } from "express";
import {
  approveDeviceHandler,
  cliLogoutHandler,
  listMyDevicesHandler,
  pollDeviceHandler,
  refreshTokenHandler,
  revokeDeviceHandler,
  startDeviceHandler,
  whoamiHandler,
} from "../controllers/device.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

export const deviceRoutes = Router();

deviceRoutes.post("/cli/device/start", startDeviceHandler);
deviceRoutes.post("/cli/device/token", pollDeviceHandler);
deviceRoutes.post("/cli/token/refresh", refreshTokenHandler);
deviceRoutes.post("/cli/device/approve", requireAuth, approveDeviceHandler);
deviceRoutes.get("/cli/whoami", requireAuth, whoamiHandler);
deviceRoutes.post("/cli/logout", requireAuth, cliLogoutHandler);
deviceRoutes.get("/me/devices", requireAuth, listMyDevicesHandler);
deviceRoutes.delete("/devices/:deviceId", requireAuth, revokeDeviceHandler);
