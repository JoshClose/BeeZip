import { useEffect, useState } from "react";
import type { CommandMap } from "./gen/commands";
import { type CmdError, type CommandInfo, listCommands, run } from "./lib/engine";
import "./App.css";

type Version = CommandMap["app.version"]["output"];

function describe(err: unknown): string {
  const e = err as Partial<CmdError>;
  return e?.code ? `${e.code}: ${e.message}` : String(err);
}

export default function App() {
  const [version, setVersion] = useState<Version>();
  const [commands, setCommands] = useState<CommandInfo[]>([]);
  const [error, setError] = useState<string>();

  useEffect(() => {
    run("app.version", {}).then(setVersion, (e) => setError(describe(e)));
    listCommands().then(setCommands, (e) => setError(describe(e)));
  }, []);

  return (
    <main className="container">
      <h1>BeeZip</h1>
      <p className="version" data-testid="version">
        {version
          ? [`BeeZip ${version.version}`, version.platform, version.profile, version.commit?.slice(0, 12)]
              .filter(Boolean)
              .join(" · ")
          : error
            ? null
            : "Loading…"}
      </p>
      {error && <p className="error">{error}</p>}

      <h2>Commands</h2>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Effect</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {commands.map((c) => (
            <tr key={c.name}>
              <td>
                <code>{c.name}</code>
              </td>
              <td>{c.effect}</td>
              <td>{c.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
