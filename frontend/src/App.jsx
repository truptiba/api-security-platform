
import { useState } from "react";
import "./App.css";

function App() {
  const [scan, setScan] = useState(null);
  const [endpoints, setEndpoints] = useState([]);
  const [findings, setFindings] = useState([]);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [loading, setLoading] = useState(false);

  const loadFindings = async (id) => {
    const res = await fetch(
      `http://127.0.0.1:8000/api/scans/${id}/findings`
    );

    const data = await res.json();
    setFindings(data.findings || []);
  };

  const loadScan = async (id) => {
    const scanRes = await fetch(
      `http://127.0.0.1:8000/api/scans/${id}`
    );

    const scanData = await scanRes.json();

    const endpointRes = await fetch(
      `http://127.0.0.1:8000/api/scans/${id}/endpoints`
    );

    const endpointData = await endpointRes.json();

    setScan(scanData.scan || scanData);
    setEndpoints(endpointData.endpoints || []);

    await loadFindings(id);

    setShowHistory(false);
  };

  const updateFinding = async (id, owner, status, dueDate) => {
    const res = await fetch(
      `http://127.0.0.1:8000/api/findings/${id}`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          owner: owner || "Security Team",
          status: status || "OPEN",
          due_date: dueDate || null,
        }),
      }
    );

    if (res.ok) {
      alert("Finding updated successfully");
    } else {
      alert("Update failed");
    }
  };

  const startScan = async () => {
    setLoading(true);

    try {
      const res = await fetch(
        "http://127.0.0.1:8000/api/scans?target_id=1",
        {
          method: "POST",
        }
      );

      const data = await res.json();

      setScan(data);

      const endpointRes = await fetch(
        `http://127.0.0.1:8000/api/scans/${data.scan_id}/endpoints`
      );

      const endpointData = await endpointRes.json();

      setEndpoints(endpointData.endpoints || []);

      await loadFindings(data.scan_id);
    } catch {
      alert("Could not connect to FastAPI");
    }

    setLoading(false);
  };

  const showScanHistory = async () => {
    const res = await fetch(
      "http://127.0.0.1:8000/api/scans"
    );

    const data = await res.json();

    setHistory(data.scans || []);
    setShowHistory(true);
  };

  const closeScan = () => {
    setScan(null);
    setEndpoints([]);
    setFindings([]);
    setShowHistory(true);
  };

  return (
    <div className="app">

      <header>
        <h1>API Security Posture Platform</h1>
        <p>Shadow Endpoint Discovery & Security Scanner</p>
      </header>

      <main>

        <section className="card">
          <h2>Scan Target API</h2>

          <p>
            Target: <strong>Demo API</strong>
          </p>

          <p className="url">
            http://localhost:8001
          </p>

          <div className="buttons">

            <button
              onClick={startScan}
              disabled={loading}
            >
              {loading ? "Scanning..." : "Start Security Scan"}
            </button>

            <button
              className="history-btn"
              onClick={showScanHistory}
            >
              Scan History
            </button>

          </div>
        </section>

        {scan && (
          <>

            <section className="dashboard">

              <div className="stat">
                <h3>Total Endpoints</h3>
                <strong>{scan.total_endpoints}</strong>
              </div>

              <div className="stat">
                <h3>Shadow Endpoints</h3>
                <strong>{scan.shadow_endpoints}</strong>
              </div>

              <div className="stat">
                <h3>Risk Score</h3>
                <strong>{scan.risk_score}</strong>
                <p>{scan.risk_level}</p>
              </div>

            </section>

            <section className="card">

              <h2>Endpoint Inventory</h2>

              <table>

                <thead>

                  <tr>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Documented</th>
                    <th>Discovered</th>
                    <th>Source</th>
                  </tr>

                </thead>

                <tbody>

                  {endpoints.map((e) => (

                    <tr key={e.endpoint_id}>

                      <td>{e.method}</td>

                      <td>{e.path}</td>

                      <td>
                        {e.documented ? "Yes" : "No"}
                      </td>

                      <td>
                        {e.discovered ? "Yes" : "No"}
                      </td>

                      <td>{e.source}</td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </section>

            <section className="card">

              <h2>Security Findings</h2>

              {findings.length === 0 ? (

                <div className="secure">
                  ✓ No security findings detected.
                </div>

              ) : (

                findings.map((f) => (

                  <div
                    className="finding"
                    key={f.finding_id}
                  >

                    <h3>{f.title}</h3>

                    <p>
                      <strong>Severity:</strong>{" "}
                      {f.severity}
                    </p>

                    <p>
                      <strong>Rule:</strong>{" "}
                      {f.rule_id}
                    </p>

                    <p>
                      {f.description}
                    </p>

                    <p>
                      <strong>Evidence:</strong>{" "}
                      {f.evidence}
                    </p>

                    <p>
                      <strong>Remediation:</strong>{" "}
                      {f.remediation}
                    </p>

                    <div className="remediation">

                      <label>Owner</label>

                      <input
                        id={`owner-${f.finding_id}`}
                        defaultValue={
                          f.owner || "Security Team"
                        }
                      />

                      <label>Status</label>

                      <select
                        id={`status-${f.finding_id}`}
                        defaultValue={
                          f.status || "OPEN"
                        }
                      >

                        <option>OPEN</option>
                        <option>IN PROGRESS</option>
                        <option>CLOSED</option>

                      </select>

                      <label>Due Date</label>

                      <input
                        id={`date-${f.finding_id}`}
                        type="date"
                        defaultValue={
                          f.due_date
                            ? f.due_date.substring(0, 10)
                            : ""
                        }
                      />

                      <button
                        onClick={() =>
                          updateFinding(
                            f.finding_id,

                            document.getElementById(
                              `owner-${f.finding_id}`
                            ).value,

                            document.getElementById(
                              `status-${f.finding_id}`
                            ).value,

                            document.getElementById(
                              `date-${f.finding_id}`
                            ).value
                          )
                        }
                      >
                        Save Remediation
                      </button>

                    </div>

                    <h4>Exception Request</h4>

                    <input
                      id={`requester-${f.finding_id}`}
                      placeholder="Requested by"
                      defaultValue=""
                    />

                    <textarea
                      id={`reason-${f.finding_id}`}
                      placeholder="Reason for exception"
                      defaultValue=""
                    />

                    {/* CREATE EXCEPTION */}

                    <button
                      onClick={async () => {

                        const requester =
                          document.getElementById(
                            `requester-${f.finding_id}`
                          ).value;

                        const reason =
                          document.getElementById(
                            `reason-${f.finding_id}`
                          ).value;

                        if (!requester || !reason) {

                          alert(
                            "Enter requester and reason."
                          );

                          return;
                        }

                        try {

                          const res = await fetch(
                            `http://127.0.0.1:8000/api/findings/${f.finding_id}/exceptions`,
                            {
                              method: "POST",

                              headers: {
                                "Content-Type":
                                  "application/json",
                              },

                              body: JSON.stringify({
                                requested_by:
                                  requester,

                                reason: reason,
                              }),
                            }
                          );

                          const data =
                            await res.json();

                          if (res.ok) {

                            alert(
                              "Exception request created successfully. Status: PENDING"
                            );

                          } else {

                            alert(
                              data.detail ||
                                "Could not create exception."
                            );

                          }

                        } catch (error) {

                          alert(
                            "Could not connect to FastAPI."
                          );

                        }

                      }}
                    >
                      Create Exception
                    </button>

                    {/* REVIEW EXCEPTION */}

                    <button
                      onClick={async () => {

                        try {

                          const res =
                            await fetch(
                              `http://127.0.0.1:8000/api/findings/${f.finding_id}/exceptions`
                            );

                          const data =
                            await res.json();

                          if (
                            !data.exceptions ||
                            !data.exceptions.length
                          ) {

                            alert(
                              "No exception found."
                            );

                            return;
                          }

                          const exception =
                            data.exceptions[0];

                          if (
                            exception.status !==
                            "PENDING"
                          ) {

                            alert(
                              `Exception Status: ${exception.status}`
                            );

                            return;
                          }

                          const approve =
                            window.confirm(
                              "Approve this exception?\n\nOK = Approve\nCancel = Reject"
                            );

                          const status =
                            approve
                              ? "APPROVED"
                              : "REJECTED";

                          const update =
                            await fetch(
                              `http://127.0.0.1:8000/api/exceptions/${exception.exception_id}`,
                              {
                                method: "PUT",

                                headers: {
                                  "Content-Type":
                                    "application/json",
                                },

                                body: JSON.stringify({
                                  status: status,
                                }),
                              }
                            );

                          if (update.ok) {

                            alert(
                              `Exception ${status}`
                            );

                          } else {

                            const errorData =
                              await update.json();

                            alert(
                              errorData.detail ||
                                "Could not update exception."
                            );

                          }

                        } catch (error) {

                          alert(
                            "Could not connect to FastAPI."
                          );

                        }

                      }}
                    >
                      Review Exception
                    </button>

                  </div>

                ))

              )}

            </section>

            <section className="card">

              <div className="section-header">

                <h2>Scan Information</h2>

                <button onClick={closeScan}>
                  Close Scan
                </button>

              </div>

              <p>
                <strong>Scan ID:</strong>{" "}
                {scan.scan_id}
              </p>

              <p>
                <strong>Status:</strong>{" "}
                Completed
              </p>

            </section>

          </>
        )}

        {showHistory && (

          <section className="card">

            <div className="section-header">

              <h2>Scan History</h2>

              <button
                onClick={() =>
                  setShowHistory(false)
                }
              >
                Close
              </button>

            </div>

            <table>

              <thead>

                <tr>
                  <th>ID</th>
                  <th>Status</th>
                  <th>Endpoints</th>
                  <th>Shadow</th>
                  <th>Risk</th>
                  <th>Level</th>
                  <th></th>
                </tr>

              </thead>

              <tbody>

                {history.map((item) => (

                  <tr key={item.scan_id}>

                    <td>{item.scan_id}</td>

                    <td>{item.status}</td>

                    <td>
                      {item.total_endpoints}
                    </td>

                    <td>
                      {item.shadow_endpoints}
                    </td>

                    <td>{item.risk_score}</td>

                    <td>{item.risk_level}</td>

                    <td>

                      <button
                        onClick={() =>
                          loadScan(
                            item.scan_id
                          )
                        }
                      >
                        View
                      </button>

                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          </section>

        )}

      </main>

    </div>
  );
}

export default App;
