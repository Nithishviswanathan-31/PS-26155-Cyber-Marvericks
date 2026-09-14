import { createTheme } from "@mui/material/styles";

export const theme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#6ea8fe" },
    secondary: { main: "#25d0b1" },
    background: { default: "#071426", paper: "#0d2038" },
  },
  typography: {
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
    h4: { fontWeight: 700 },
  },
  shape: { borderRadius: 12 },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundImage: "radial-gradient(circle at 85% 10%, rgba(37,208,177,0.08), transparent 28%), radial-gradient(circle at 15% 0%, rgba(110,168,254,0.08), transparent 24%)",
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          border: "1px solid rgba(255,255,255,0.07)",
        },
      },
    },
  },
});
