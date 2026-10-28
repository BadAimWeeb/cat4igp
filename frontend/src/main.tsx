/// <reference types="vite/client" />
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles/style.css";

createRoot(document.getElementById("root")!).render(<App />);
