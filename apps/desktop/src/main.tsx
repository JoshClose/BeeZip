import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { JobWindow } from "./features/job/JobWindow";
import { startup } from "./lib/startup";
import "./index.css";

// A job window (`job-*`) gets its steps with its startup data and shows only them (docs/M4.md
// §6.3); every other window is the main one.
const job = startup().job;

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>{job ? <JobWindow job={job} /> : <App />}</React.StrictMode>,
);
