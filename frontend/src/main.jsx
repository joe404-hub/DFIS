import React from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import App from "./App.jsx";

const theme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#3dd6c6" },
    secondary: { main: "#f4b942" },
    background: { default: "#071018", paper: "#0e1a24" },
    error: { main: "#ff6b6b" },
  },
  typography: {
    fontFamily: '"IBM Plex Sans", sans-serif',
    h5: { fontWeight: 700, letterSpacing: 0.3 },
    h6: { fontWeight: 600 },
  },
  shape: { borderRadius: 10 },
});

ReactDOM.createRoot(document.getElementById("root")).render(
  <ThemeProvider theme={theme}>
    <CssBaseline />
    <App />
  </ThemeProvider>
);
