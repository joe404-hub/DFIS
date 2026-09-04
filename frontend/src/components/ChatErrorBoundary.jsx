import React, { Component } from "react";
import { Paper, Typography } from "@mui/material";
import MarkdownView from "./MarkdownView.jsx";

export default class ChatErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("Chat rendering error:", error, errorInfo);
  }
  componentDidUpdate(prevProps) {
    if (prevProps.fallbackText !== this.props.fallbackText && this.state.hasError) {
      this.setState({ hasError: false, error: null });
    }
  }
  render() {
    if (this.state.hasError) {
      return (
        <Paper sx={{ p: 2, bgcolor: "#141005", border: "1px solid rgba(246, 184, 74, 0.3)", borderRadius: "10px", mt: 1 }}>
          <Typography variant="subtitle2" sx={{ color: "#f6b84a", fontWeight: 700, mb: 1 }}>
            Investigation Response
          </Typography>
          <MarkdownView content={this.props.fallbackText} />
        </Paper>
      );
    }
    return this.props.children;
  }
}
