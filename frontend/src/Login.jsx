import { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const API =
  import.meta.env.VITE_API_BASE ||
  "https://safechatai-backend.onrender.com";

console.log("AUTH API =", API);

export default function Login({ onLogin }) {
  const [isSignup, setIsSignup] = useState(false);
  const [isForgotPassword, setIsForgotPassword] = useState(false);
  const [resetEmail, setResetEmail] = useState("");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const [fullName, setFullName] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [industry, setIndustry] = useState("");
  const [email, setEmail] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const navigate = useNavigate();
const requestPasswordReset = async () => {
  if (loading) return;

  if (!resetEmail.trim()) {
    setError("Please enter your email address.");
    return;
  }

  setError("");
  setLoading(true);

  try {
    const res = await axios.post(`${API}/forgot-password`, {
      email: resetEmail.trim(),
    });

    if (res.data.success) {
      setError("");
      alert(
        res.data.message ||
          "If an account exists for this email, a reset request has been created."
      );
    } else {
      setError(
        res.data.message ||
          "Unable to process password reset."
      );
    }
  } catch (err) {
    console.error("PASSWORD RESET ERROR:", err);

    setError(
      err.response?.data?.detail ||
        err.response?.data?.message ||
        "Unable to connect to the SafeChat AI server."
    );
  } finally {
    setLoading(false);
  }
};

  const authenticate = async () => {
    if (loading) return;

    // -----------------------------
    // BASIC VALIDATION
    // -----------------------------
    if (!username.trim() || !password) {
      setError("Please enter your username and password.");
      return;
    }

    if (isSignup) {
      if (
        !fullName.trim() ||
        !companyName.trim() ||
        !industry ||
        !email.trim() ||
        !username.trim() ||
        !password ||
        !confirmPassword
      ) {
        setError("Please complete all fields.");
        return;
      }

      if (password !== confirmPassword) {
        setError("Passwords do not match.");
        return;
      }
    }

    setError("");
    setLoading(true);

    try {
      // ============================================================
      // SIGNUP
      // ============================================================
      if (isSignup) {
        const res = await axios.post(`${API}/signup`, {
          full_name: fullName.trim(),
          company_name: companyName.trim(),
          industry,
          email: email.trim(),
          username: username.trim(),
          password,
        });

        console.log("SIGNUP RESPONSE =", res.data);

        if (!res.data.success) {
          setError(
            res.data.message ||
              "Unable to create account."
          );
          return;
        }

        // Save authentication
        localStorage.setItem("token", res.data.token);
        localStorage.setItem("role", res.data.role);
        localStorage.setItem(
          "tenant_id",
          res.data.tenant_id
        );

        if (onLogin) {
          onLogin(res.data.role);
        }

        // New organizations go to customer dashboard
        navigate("/customer");

        return;
      }

      // ============================================================
      // LOGIN
      // ============================================================
      const res = await axios.post(`${API}/login`, {
        username: username.trim(),
        password,
      });

      console.log("LOGIN RESPONSE =", res.data);

      if (!res.data.success) {
        setError(
          res.data.message ||
            "Login failed."
        );
        return;
      }

      // Save authentication
      localStorage.setItem("token", res.data.token);
      localStorage.setItem("role", res.data.role);
      localStorage.setItem(
        "tenant_id",
        res.data.tenant_id
      );

      if (onLogin) {
        onLogin(res.data.role);
      }

      // ============================================================
// SINGLE DASHBOARD ROUTING
// ============================================================
navigate("/dashboard");

    } catch (err) {
      console.error("AUTH ERROR:", err);

      if (err.response) {
        console.error(
          "STATUS:",
          err.response.status
        );

        console.error(
          "DATA:",
          err.response.data
        );

        setError(
          err.response.data?.detail ||
            err.response.data?.message ||
            "Authentication failed."
        );
      } else {
        setError(
          "Unable to connect to the SafeChat AI server."
        );
      }

    } finally {
      setLoading(false);
    }
  };

  // ================================================================
  // ENTER KEY
  // ================================================================
  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !loading) {
      authenticate();
    }
  };

  // ================================================================
  // SWITCH LOGIN / SIGNUP
  // ================================================================
  const switchMode = () => {
    setIsSignup((current) => !current);

    setError("");
    setPassword("");
    setConfirmPassword("");
  };

  return (
    <div className="login-page">

      {/* Background grid */}
      <div className="login-grid" />

      {/* Ambient glow */}
      <div className="login-glow login-glow-one" />
      <div className="login-glow login-glow-two" />

      <div className="login-container">

        {/* ========================================================
            BRAND
        ======================================================== */}
        <div className="login-brand">

          <div className="brand-icon">
            🛡️
          </div>

          <div>
            <div className="brand-name">
              SafeChat <span>AI</span>
            </div>

            <div className="brand-subtitle">
              SECURITY OPERATIONS CENTER
            </div>
          </div>

        </div>

        {/* ========================================================
            AUTH CARD
        ======================================================== */}
        <div className="login-card">
{isForgotPassword ? (
  <div className="login-card-header">

    <div className="status-line">
      <span className="status-dot" />
      PASSWORD RECOVERY
    </div>

    <h1>Forgot your password?</h1>

    <p>
      Enter your account email and we'll help you reset
      your password securely.
    </p>

    {error && (
      <div className="login-error">
        <span>⚠️ </span>
        <span>{error}</span>
      </div>
    )}

    <div className="input-group">

      <label>EMAIL ADDRESS</label>

      <div className="input-wrapper">

        <span className="input-icon">@</span>

        <input
          type="email"
          placeholder="security@company.com"
          value={resetEmail}
          onChange={(e) =>
            setResetEmail(e.target.value)
          }
          autoComplete="email"
        />

      </div>

    </div>

    <button
      className={`login-button ${
        loading ? "loading" : ""
      }`}
      onClick={requestPasswordReset}
      disabled={loading}
    >
      {loading
        ? "PROCESSING..."
        : "SEND RESET REQUEST"}
    </button>

    <div className="auth-switch">

      <button
        type="button"
        onClick={() => {
          setIsForgotPassword(false);
          setResetEmail("");
          setError("");
        }}
      >
        ← Back to sign in
      </button>

    </div>

  </div>
) : (
  <>

          <div className="login-card-header">

            <div className="status-line">
              <span className="status-dot" />

              {isSignup
                ? "CREATE SECURE WORKSPACE"
                : "SYSTEM ONLINE"}
            </div>

            <h1>
              {isSignup
                ? "Create your account"
                : "Welcome back"}
            </h1>

            <p>
              {isSignup
                ? "Create your organization's secure SOC workspace."
                : "Sign in to access your security operations dashboard."}
            </p>

          </div>

          {/* ======================================================
              ERROR
          ====================================================== */}
          {error && (
            <div className="login-error">
              <span>⚠️ </span>
              <span>{error}</span>
            </div>
          )}

          {/* ======================================================
              SIGNUP FIELDS
          ====================================================== */}
          {isSignup && (
            <>
              {/* Full Name */}
              <div className="input-group">

                <label>FULL NAME</label>

                <div className="input-wrapper">

                  <span className="input-icon">
                    👤
                  </span>

                  <input
                    type="text"
                    placeholder="Your full name"
                    value={fullName}
                    onChange={(e) =>
                      setFullName(e.target.value)
                    }
                    onKeyDown={handleKeyDown}
                    autoComplete="name"
                  />

                </div>
              </div>

              {/* Company */}
              <div className="input-group">

                <label>COMPANY NAME</label>

                <div className="input-wrapper">

                  <span className="input-icon">
                    ◈
                  </span>

                  <input
                    type="text"
                    placeholder="Your organization"
                    value={companyName}
                    onChange={(e) =>
                      setCompanyName(e.target.value)
                    }
                    onKeyDown={handleKeyDown}
                    autoComplete="organization"
                  />

                </div>
              </div>

              {/* Industry */}
              <div className="input-group">

                <label>INDUSTRY</label>

                <div className="input-wrapper">

                  <span className="input-icon">
                    🔒
                  </span>

                  <select
                    value={industry}
                    onChange={(e) =>
                      setIndustry(e.target.value)
                    }
                  >
                    <option value="">
                      Select industry
                    </option>

                    <option value="Technology">
                      Technology
                    </option>

                    <option value="Finance">
                      Finance
                    </option>

                    <option value="Healthcare">
                      Healthcare
                    </option>

                    <option value="Education">
                      Education
                    </option>

                    <option value="Government">
                      Government
                    </option>

                    <option value="Retail">
                      Retail
                    </option>

                    <option value="Telecommunications">
                      Telecommunications
                    </option>

                    <option value="Other">
                      Other
                    </option>

                  </select>

                </div>
              </div>

              {/* Email */}
              <div className="input-group">

                <label>EMAIL</label>

                <div className="input-wrapper">

                  <span className="input-icon">
                    @
                  </span>

                  <input
                    type="email"
                    placeholder="security@company.com"
                    value={email}
                    onChange={(e) =>
                      setEmail(e.target.value)
                    }
                    onKeyDown={handleKeyDown}
                    autoComplete="email"
                  />

                </div>
              </div>
            </>
          )}

          {/* ======================================================
              USERNAME
          ====================================================== */}
          <div className="input-group">

            <label>USERNAME</label>

            <div className="input-wrapper">

              <span className="input-icon">
                👤
              </span>

              <input
                type="text"
                placeholder="Enter your username"
                value={username}
                onChange={(e) =>
                  setUsername(e.target.value)
                }
                onKeyDown={handleKeyDown}
                autoComplete="username"
              />

            </div>
          </div>

          {/* ======================================================
              PASSWORD
          ====================================================== */}
          <div className="input-group">

            <label>PASSWORD</label>

            <div className="input-wrapper">

              <span className="input-icon">
                🔒
              </span>

              <input
                type={
                  showPassword
                    ? "text"
                    : "password"
                }
                placeholder="Enter your password"
                value={password}
                onChange={(e) =>
                  setPassword(e.target.value)
                }
                onKeyDown={handleKeyDown}
                autoComplete={
                  isSignup
                    ? "new-password"
                    : "current-password"
                }
              />

              <button
                type="button"
                className="password-toggle"
                onClick={() =>
                  setShowPassword(
                    !showPassword
                  )
                }
              >
                {showPassword
                  ? "Hide"
                  : "Show"}
              </button>

            </div>
          </div>

          {/* ======================================================
              CONFIRM PASSWORD
          ====================================================== */}
          {isSignup && (
            <div className="input-group">

              <label>CONFIRM PASSWORD</label>

              <div className="input-wrapper">

                <span className="input-icon">
                  🔒
                </span>

                <input
                  type={
                    showPassword
                      ? "text"
                      : "password"
                  }
                  placeholder="Confirm your password"
                  value={confirmPassword}
                  onChange={(e) =>
                    setConfirmPassword(
                      e.target.value
                    )
                  }
                  onKeyDown={handleKeyDown}
                  autoComplete="new-password"
                />

              </div>
            </div>
          )}

          {/* ======================================================
              AUTH BUTTON
          ====================================================== */}
          <button
            className={`login-button ${
              loading ? "loading" : ""
            }`}
            onClick={authenticate}
            disabled={loading}
          >

            {loading ? (
              <>
                <span className="spinner" />

                {isSignup
                  ? "CREATING ACCOUNT..."
                  : "AUTHENTICATING..."}
              </>
            ) : (
              <>
                {isSignup
                  ? "CREATE SECURE ACCOUNT"
                  : "SIGN IN"}

                <span className="login-arrow">
                  →
                </span>
              </>
            )}

          </button>

          {/* ======================================================
              SECURITY INFORMATION
          ====================================================== */}
          <div className="security-info">

            <div>
              <span>●</span>
              Protected session
            </div>

            <div>
              <span>●</span>
              AI threat monitoring
            </div>

          </div>

          {/* ======================================================
    LOGIN / SIGNUP SWITCH
====================================================== */}

{!isSignup && (
  <div
    style={{
      marginTop: "18px",
      marginBottom: "14px",
      textAlign: "center",
    }}
  >
    <button
      type="button"
      onClick={() => {
        setIsForgotPassword(true);
        setError("");
      }}
      style={{
        border: "none",
        background: "transparent",
        color: "#00ffc8",
        fontSize: "11px",
        fontWeight: 800,
        cursor: "pointer",
      }}
    >
      Forgot password?
    </button>
  </div>
)}

<div className="auth-switch">

  {isSignup ? (
    <>
      <span>
        Already have an account?
      </span>

      <button
        type="button"
        onClick={switchMode}
      >
        Sign in
      </button>
    </>
  ) : (
    <>
      <span>
        Don't have an account?
      </span>

      <button
        type="button"
        onClick={switchMode}
      >
        Create account
      </button>
    </>
  )}

</div>
  </>
)}

        </div>

        {/* ========================================================
            FOOTER
        ======================================================== */}
        <div className="login-footer">

          <span>SAFECHAT AI SOC</span>

          <span>•</span>

          <span>SECURE ACCESS</span>

        </div>

      </div>

      {/* ==========================================================
          STYLES
      ========================================================== */}
      <style>{`

        * {
          box-sizing: border-box;
        }

        .login-page {
          min-height: 100vh;
          width: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
          position: relative;
          overflow: hidden;
          background:
            radial-gradient(
              circle at 50% 20%,
              rgba(0, 255, 200, 0.08),
              transparent 35%
            ),
            #020617;
          color: #e2e8f0;
          font-family:
            Inter,
            ui-sans-serif,
            system-ui,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;
        }

        .login-grid {
          position: absolute;
          inset: 0;
          opacity: 0.18;

          background-image:
            linear-gradient(
              rgba(0, 255, 200, 0.08) 1px,
              transparent 1px
            ),
            linear-gradient(
              90deg,
              rgba(0, 255, 200, 0.08) 1px,
              transparent 1px
            );

          background-size: 45px 45px;

          mask-image:
            linear-gradient(
              to bottom,
              black,
              transparent 90%
            );
        }

        .login-glow {
          position: absolute;
          width: 450px;
          height: 450px;
          border-radius: 50%;
          filter: blur(100px);
          pointer-events: none;
        }

        .login-glow-one {
          top: -250px;
          left: -200px;
          background:
            rgba(0, 255, 200, 0.08);
        }

        .login-glow-two {
          right: -250px;
          bottom: -250px;
          background:
            rgba(37, 99, 235, 0.08);
        }

        .login-container {
          position: relative;
          z-index: 2;
          width: min(430px, calc(100% - 32px));

          display: flex;
          flex-direction: column;
          align-items: center;
        }

        .login-brand {
          display: flex;
          align-items: center;
          gap: 13px;
          margin-bottom: 24px;
        }

        .brand-icon {
          width: 48px;
          height: 48px;

          border:
            1px solid
            rgba(0, 255, 200, 0.35);

          border-radius: 13px;

          display: flex;
          align-items: center;
          justify-content: center;

          font-size: 24px;

          background:
            rgba(0, 255, 200, 0.07);

          box-shadow:
            0 0 25px
            rgba(0, 255, 200, 0.08);
        }

        .brand-name {
          font-size: 22px;
          font-weight: 800;
          letter-spacing: -0.5px;
          color: #f8fafc;
        }

        .brand-name span {
          color: #00ffc8;
        }

        .brand-subtitle {
          margin-top: 3px;
          color: #64748b;
          font-size: 9px;
          font-weight: 700;
          letter-spacing: 2px;
        }

        .login-card {
          width: 100%;
          padding: 32px;

          border-radius: 20px;

          border:
            1px solid
            rgba(148, 163, 184, 0.14);

          background:
            linear-gradient(
              145deg,
              rgba(15, 23, 42, 0.96),
              rgba(8, 15, 29, 0.96)
            );

          box-shadow:
            0 30px 80px
            rgba(0, 0, 0, 0.45),

            inset 0 1px
            rgba(255, 255, 255, 0.035);

          backdrop-filter: blur(20px);
        }

        .login-card-header {
          margin-bottom: 27px;
        }

        .status-line {
          display: flex;
          align-items: center;
          gap: 7px;

          color: #4ade80;

          font-size: 10px;
          font-weight: 800;
          letter-spacing: 1.5px;

          margin-bottom: 14px;
        }

        .status-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;

          background: #4ade80;

          box-shadow:
            0 0 10px
            rgba(74, 222, 128, 0.8);
        }

        .login-card h1 {
          margin: 0;

          color: #f8fafc;

          font-size: 29px;
          line-height: 1.2;
          letter-spacing: -0.8px;
        }

        .login-card-header p {
          margin: 9px 0 0;

          color: #64748b;

          font-size: 13px;
          line-height: 1.6;
        }

        .login-error {
          display: flex;
          align-items: flex-start;
          gap: 9px;

          margin-bottom: 18px;
          padding: 12px 13px;

          border-radius: 10px;

          border:
            1px solid
            rgba(248, 113, 113, 0.25);

          background:
            rgba(127, 29, 29, 0.18);

          color: #fca5a5;

          font-size: 12px;
          line-height: 1.5;
        }

        .input-group {
          margin-bottom: 18px;
        }

        .input-group label {
          display: block;

          margin-bottom: 8px;

          color: #94a3b8;

          font-size: 10px;
          font-weight: 800;
          letter-spacing: 1.4px;
        }

        .input-wrapper {
          position: relative;

          display: flex;
          align-items: center;
        }

        .input-wrapper input,
        .input-wrapper select {
          width: 100%;
          height: 50px;

          padding: 0 45px 0 43px;

          border:
            1px solid
            #1e293b;

          border-radius: 11px;

          outline: none;

          background: #020617;

          color: #f8fafc;

          font-size: 14px;

          transition:
            all 0.2s ease;
        }

        .input-wrapper select {
          appearance: none;
          cursor: pointer;
        }

        .input-wrapper input::placeholder {
          color: #475569;
        }

        .input-wrapper input:focus,
        .input-wrapper select:focus {
          border-color:
            rgba(0, 255, 200, 0.55);

          box-shadow:
            0 0 0 3px
            rgba(0, 255, 200, 0.07);
        }

        .input-icon {
          position: absolute;
          left: 15px;

          color: #64748b;

          font-size: 13px;

          z-index: 1;
        }

        .password-toggle {
          position: absolute;
          right: 10px;

          border: none;

          background: transparent;

          color: #64748b;

          cursor: pointer;

          font-size: 11px;
          font-weight: 700;
        }

        .password-toggle:hover {
          color: #00ffc8;
        }

        .login-button {
          width: 100%;
          min-height: 51px;

          margin-top: 5px;

          display: flex;
          align-items: center;
          justify-content: center;

          gap: 10px;

          border: none;
          border-radius: 11px;

          background:
            linear-gradient(
              135deg,
              #00ffc8,
              #00d9ad
            );

          color: #02110d;

          font-size: 12px;
          font-weight: 900;
          letter-spacing: 1.3px;

          cursor: pointer;

          transition:
            transform 0.2s ease,
            box-shadow 0.2s ease,
            opacity 0.2s ease;

          box-shadow:
            0 8px 25px
            rgba(0, 255, 200, 0.16);
        }

        .login-button:hover:not(:disabled) {
          transform: translateY(-1px);

          box-shadow:
            0 12px 30px
            rgba(0, 255, 200, 0.25);
        }

        .login-button:active:not(:disabled) {
          transform: translateY(0);
        }

        .login-button:disabled {
          cursor: not-allowed;
          opacity: 0.7;
        }

        .login-arrow {
          font-size: 18px;
          line-height: 0;
        }

        .spinner {
          width: 15px;
          height: 15px;

          border:
            2px solid
            rgba(2, 17, 13, 0.25);

          border-top-color: #02110d;

          border-radius: 50%;

          animation:
            spin 0.7s linear infinite;
        }

        @keyframes spin {
          to {
            transform: rotate(360deg);
          }
        }

        .security-info {
          display: flex;
          justify-content: center;

          gap: 20px;

          margin-top: 22px;

          color: #475569;

          font-size: 10px;
        }

        .security-info div {
          display: flex;
          align-items: center;

          gap: 5px;
        }

        .security-info span {
          color: #22c55e;
          font-size: 7px;
        }

        .auth-switch {
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 5px;

          margin-top: 22px;

          color: #64748b;

          font-size: 11px;
        }

        .auth-switch button {
          border: none;
          background: transparent;

          color: #00ffc8;

          font-size: 11px;
          font-weight: 800;

          cursor: pointer;
        }

        .auth-switch button:hover {
          text-decoration: underline;
        }

        .login-footer {
          display: flex;
          align-items: center;

          gap: 8px;

          margin-top: 20px;

          color: #334155;

          font-size: 9px;
          font-weight: 700;

          letter-spacing: 1.3px;
        }

        @media (max-width: 520px) {

          .login-card {
            padding: 25px 21px;
          }

          .login-brand {
            margin-bottom: 19px;
          }

          .security-info {
            flex-direction: column;
            align-items: center;
            gap: 7px;
          }

          .auth-switch {
            flex-wrap: wrap;
            text-align: center;
          }

        }

      `}</style>

    </div>
  );
}
