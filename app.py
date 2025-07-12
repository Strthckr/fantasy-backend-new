// AdminUsers.jsx

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

const AdminUsers = () => {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [minBalance, setMinBalance] = useState("");
  const [maxBalance, setMaxBalance] = useState("");
  const [showAdminsOnly, setShowAdminsOnly] = useState(false);
  const [showNeverJoined, setShowNeverJoined] = useState(false);
  const [showInactive, setShowInactive] = useState(false);
  const [showLossAboveEarning, setShowLossAboveEarning] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [sortOrder, setSortOrder] = useState("desc");
  const navigate = useNavigate();

  // Fetch users from backend
  const fetchUsers = async () => {
    try {
      const res = await fetch(
        "https://fantasy-backend-new.onrender.com/admin/users",
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`
          }
        }
      );
      const data = await res.json();
      if (!res.ok || !Array.isArray(data)) {
        throw new Error(data.message || "Invalid response");
      }
      setUsers(data);
    } catch (err) {
      console.error("❌ Failed to load users:", err);
      setError(err.message || "Unexpected error");
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  // Admin actions
  const resetPassword = async (userId) => {
    const newPass = window.prompt("🔐 Enter new password for this user:");
    if (!newPass || newPass.length < 6) {
      alert("Password must be at least 6 characters.");
      return;
    }
    try {
      const res = await fetch(
        "https://fantasy-backend-new.onrender.com/admin/reset_password",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("token")}`
          },
          body: JSON.stringify({ user_id: userId, new_password: newPass })
        }
      );
      const data = await res.json();
      alert(data.message || "✅ Password reset successfully");
    } catch {
      alert("❌ Password reset failed");
    }
  };

  const viewTransactions = (userId) => {
    navigate(`/admin/users/${userId}/transactions`);
  };

  const viewEarnings = (userId) => {
    navigate(`/admin/users/${userId}/earnings`);
  };

  const adjustWallet = async (userId) => {
    const amt = parseFloat(prompt("Enter amount (＋ credit, – debit):"));
    if (!amt) return;
    const note = prompt("Optional note:");
    try {
      await fetch(
        "https://fantasy-backend-new.onrender.com/admin/wallet_adjust",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("token")}`
          },
          body: JSON.stringify({ user_id: userId, amount: amt, note })
        }
      );
      fetchUsers();
    } catch {
      alert("❌ Wallet adjustment failed");
    }
  };

  const toggleAdmin = async (userId) => {
    try {
      await fetch(
        "https://fantasy-backend-new.onrender.com/admin/toggle_admin",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("token")}`
          },
          body: JSON.stringify({ user_id: userId })
        }
      );
      fetchUsers();
    } catch {
      alert("❌ Failed to toggle admin status");
    }
  };

  const banUser = async (userId) => {
    try {
      await fetch(
        "https://fantasy-backend-new.onrender.com/admin/ban_user",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("token")}`
          },
          body: JSON.stringify({ user_id: userId })
        }
      );
      fetchUsers();
    } catch {
      alert("❌ Failed to ban/unban user");
    }
  };

  // CSV Export
  const downloadCSV = () => {
    if (!filteredUsers.length) return;
    const headers = [
      "User ID,Username,Email,Wallet,Total Earning,Total Loss,Contests Joined,Last Played,Admin,Banned,Joined On"
    ];
    const rows = filteredUsers.map((u) =>
      [
        u.user_id,
        `"${u.name || "—"}"`,
        u.email,
        u.wallet.toFixed(2),
        u.total_earning.toFixed(2),
        u.total_loss.toFixed(2),
        u.contest_count,
        u.last_contest_date
          ? new Date(u.last_contest_date).toLocaleDateString()
          : "—",
        u.is_admin ? "Yes" : "No",
        u.is_banned ? "Yes" : "No",
        u.registered_at
          ? new Date(u.registered_at).toLocaleDateString()
          : "—"
      ].join(",")
    );
    const csvContent = [...headers, ...rows].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "admin_users.csv";
    a.click();
  };

  // Filters & sorting
  const today = new Date();
  const filteredUsers = users
    .filter((u) => {
      const wallet = u.wallet || 0;
      const matchesSearch =
        u.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u.email.toLowerCase().includes(searchTerm.toLowerCase());

      const neverJoinedOk = !showNeverJoined || u.contest_count === 0;
      const inactiveOk = !showInactive || (() => {
        if (!u.last_contest_date) return false;
        const diffDays =
          (today - new Date(u.last_contest_date)) / (1000 * 60 * 60 * 24);
        return diffDays >= 7;
      })();
      const lossAboveEarningOk =
        !showLossAboveEarning || u.total_loss > u.total_earning;

      return (
        matchesSearch &&
        (!minBalance || wallet >= parseFloat(minBalance)) &&
        (!maxBalance || wallet <= parseFloat(maxBalance)) &&
        (!showAdminsOnly || u.is_admin) &&
        neverJoinedOk &&
        inactiveOk &&
        lossAboveEarningOk
      );
    })
    .sort((a, b) =>
      sortOrder === "asc" ? a.wallet - b.wallet : b.wallet - a.wallet
    );

  // Summaries
  const totalWallet = filteredUsers.reduce((sum, u) => sum + u.wallet, 0);
  const totalEarning = filteredUsers.reduce(
    (sum, u) => sum + u.total_earning,
    0
  );
  const totalLoss = filteredUsers.reduce((sum, u) => sum + u.total_loss, 0);
  const totalContests = filteredUsers.reduce(
    (sum, u) => sum + u.contest_count,
    0
  );

  return (
    <div style={{ padding: "20px" }}>
      <h2>👥 All Users</h2>

      {/* Filters */}
      <div
        style={{
          marginBottom: "1rem",
          display: "flex",
          flexWrap: "wrap",
          gap: "1rem"
        }}
      >
        <label>
          Min ₹{" "}
          <input
            type="number"
            value={minBalance}
            onChange={(e) => setMinBalance(e.target.value)}
          />
        </label>
        <label>
          Max ₹{" "}
          <input
            type="number"
            value={maxBalance}
            onChange={(e) => setMaxBalance(e.target.value)}
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={showAdminsOnly}
            onChange={(e) => setShowAdminsOnly(e.target.checked)}
          />{" "}
          Show only Admins
        </label>
        <label>
          🔍 Search{" "}
          <input
            type="text"
            placeholder="username or email"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </label>
        <label>
          📊 Sort Wallet{" "}
          <select
            value={sortOrder}
            onChange={(e) => setSortOrder(e.target.value)}
          >
            <option value="desc">High → Low</option>
            <option value="asc">Low → High</option>
          </select>
        </label>

        {/* Behavior Filters */}
        <label>
          <input
            type="checkbox"
            checked={showNeverJoined}
            onChange={(e) => setShowNeverJoined(e.target.checked)}
          />{" "}
          Never Joined Contest
        </label>
        <label>
          <input
            type="checkbox"
            checked={showInactive}
            onChange={(e) => setShowInactive(e.target.checked)}
          />{" "}
          Inactive ≥ 7 days
        </label>
        <label>
          <input
            type="checkbox"
            checked={showLossAboveEarning}
            onChange={(e) => setShowLossAboveEarning(e.target.checked)}
          />{" "}
          Loss > Earning
        </label>

        <button onClick={downloadCSV}>📥 Export CSV</button>
        <button
          onClick={() => {
            setMinBalance("");
            setMaxBalance("");
            setSearchTerm("");
            setShowAdminsOnly(false);
            setShowNeverJoined(false);
            setShowInactive(false);
            setShowLossAboveEarning(false);
            setSortOrder("desc");
          }}
        >
          🧹 Clear Filters
        </button>
      </div>

      {/* Summary */}
      <div style={{ marginBottom: "1rem" }}>
        <strong>Filtered Users:</strong> {filteredUsers.length} |{" "}
        <strong>Total Wallet:</strong> ₹{totalWallet.toFixed(2)} |{" "}
        <strong>Total Earning:</strong> ₹{totalEarning.toFixed(2)} |{" "}
        <strong>Total Loss:</strong> ₹{totalLoss.toFixed(2)} |{" "}
        <strong>Total Contests:</strong> {totalContests}
      </div>

      {/* Table */}
      {error ? (
        <p style={{ color: "red", fontWeight: "bold" }}>❌ {error}</p>
      ) : (
        <table
          border="1"
          cellPadding="8"
          style={{ width: "100%", borderCollapse: "collapse" }}
        >
          <thead style={{ background: "#f0f0f0" }}>
            <tr>
              <th>User ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Wallet ₹</th>
              <th>Total Earning ₹</th>
              <th>Total Loss ₹</th>
              <th>Contests Joined</th>
              <th>Last Played</th>
              <th>Admin?</th>
              <th>Banned?</th>
              <th>Joined On</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredUsers.length > 0 ? (
              filteredUsers.map((u) => (
                <tr key={u.user_id}>
                  <td>{u.user_id}</td>
                  <td>{u.name || "—"}</td>
                  <td>{u.email}</td>
                  <td>₹{u.wallet.toFixed(2)}</td>
                  <td>₹{u.total_earning.toFixed(2)}</td>
                  <td>₹{u.total_loss.toFixed(2)}</td>
                  <td>{u.contest_count}</td>
                  <td>
                    {u.last_contest_date
                      ? new Date(u.last_contest_date).toLocaleDateString()
                      : "—"}
                  </td>
                  <td>{u.is_admin ? "✅" : "❌"}</td>
                  <td>{u.is_banned ? "✅" : "❌"}</td>
                  <td>
                    {u.registered_at
                      ? new Date(u.registered_at).toLocaleDateString()
                      : "—"}
                  </td>
                  <td>
                    <button onClick={() => resetPassword(u.user_id)}>
                      🔄 Reset Password
                    </button>{" "}
                    <button onClick={() => viewTransactions(u.user_id)}>
                      📜 View Transactions
                    </button>{" "}
                    <button onClick={() => viewEarnings(u.user_id)}>
                      📈 Earnings & Loss
                    </button>{" "}
                    <button onClick={() => adjustWallet(u.user_id)}>
                      💰 Adjust Wallet
                    </button>{" "}
                    <button onClick={() => toggleAdmin(u.user_id)}>
                      {u.is_admin ? "🔽 Demote" : "🔼 Promote"}
                    </button>{" "}
                    <button onClick={() => banUser(u.user_id)}>
                      {u.is_banned ? "🔓 Unban" : "⛔ Ban"}
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td
                  colSpan="12"
                  style={{ textAlign: "center", padding: "10px" }}
                >
                  No user matches the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default AdminUsers;
