import {
  AppBar,
  Avatar,
  Box,
  Chip,
  Container,
  CssBaseline,
  Divider,
  Drawer,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Toolbar,
  Typography,
} from "@mui/material";
import { Assessment, Dashboard } from "@mui/icons-material";

import { useState } from "react";

import type { AnalysisResponse } from "./api/analyze";
import AnalyzeConfigurationPage from "./pages/AnalyzeConfigurationPage";
import DashboardPage from "./pages/DashboardPage";

const drawerWidth = 248;

export default function App() {
  const [activeView, setActiveView] = useState<"dashboard" | "analyze">("dashboard");
  const [analyses, setAnalyses] = useState<AnalysisResponse[]>([]);

  const handleAnalysisCompleted = (analysis: AnalysisResponse) => {
    setAnalyses((current) => [...current, analysis]);
  };

  return (
    <Box sx={{ display: "flex", minHeight: "100vh" }}>
      <CssBaseline />
      <AppBar
        position="fixed"
        elevation={0}
        sx={{
          width: `calc(100% - ${drawerWidth}px)`,
          ml: `${drawerWidth}px`,
          bgcolor: "rgba(7, 20, 38, 0.86)",
          backdropFilter: "blur(14px)",
          borderBottom: "1px solid rgba(255,255,255,0.08)",
        }}
      >
        <Toolbar sx={{ justifyContent: "space-between" }}>
          <Typography variant="subtitle1" fontWeight={700}>
            AI-Driven Multi-Vendor Network Security Compliance Auditor
          </Typography>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <Chip label="Emergency Demo MVP · P0.14" color="secondary" variant="outlined" />
            <Avatar sx={{ width: 32, height: 32, bgcolor: "primary.main", color: "#071426" }}>C</Avatar>
          </Stack>
        </Toolbar>
      </AppBar>

      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          "& .MuiDrawer-paper": {
            width: drawerWidth,
            boxSizing: "border-box",
            bgcolor: "#091a2e",
            color: "#eaf3ff",
            borderRight: "1px solid rgba(255,255,255,0.08)",
          },
        }}
      >
        <Toolbar>
          <Stack spacing={0.25}>
            <Typography variant="h6" fontWeight={800}>
              PS 26155 AUDITOR
            </Typography>
            <Typography variant="caption" color="text.secondary">
              PS 26155 · CYBER MARVERICKS
            </Typography>
          </Stack>
        </Toolbar>
        <Divider />
        <List sx={{ px: 1.25, pt: 2 }}>
          {[
            { label: "Dashboard", view: "dashboard" as const, icon: <Dashboard fontSize="small" /> },
            { label: "Analyze Configuration", view: "analyze" as const, icon: <Assessment fontSize="small" /> },
          ].map((item) => (
            <ListItemButton
              key={item.label}
              selected={activeView === item.view}
              onClick={() => setActiveView(item.view)}
              sx={{ borderRadius: 2, mb: 0.5 }}
            >
              <Box sx={{ display: "flex", mr: 1.25, color: activeView === item.view ? "primary.main" : "text.secondary" }}>
                {item.icon}
              </Box>
              <ListItemText primary={item.label} />
            </ListItemButton>
          ))}
        </List>
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, py: 12, px: 4 }}>
        <Container maxWidth="lg">
          <Stack spacing={3}>
            {activeView === "dashboard" ? (
              <DashboardPage analyses={analyses} onAnalyze={() => setActiveView("analyze")} />
            ) : (
              <AnalyzeConfigurationPage onAnalysisCompleted={handleAnalysisCompleted} />
            )}
          </Stack>
        </Container>
      </Box>
    </Box>
  );
}
