import { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";


const API = import.meta.env.VITE_API_BASE;
console.log("MODE:", import.meta.env.MODE);
console.log("API AT LOAD:", API);

export default function Login({ onLogin }) {

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const login = async () => {
  console.log("API:", API);
  console.log("LOGIN URL:", `${API}/login`);

  try {
    const res = await axios.post(`${API}/login`, {
      username,
      password,
    });

    console.log("LOGIN RESPONSE:", res.data);

    if (!res.data.success) {
      alert(res.data.message);
      return;
    }

    localStorage.setItem("token", res.data.token);
    localStorage.setItem("role", res.data.role);

    if (onLogin) {
      onLogin(res.data.role);
    }

    switch (res.data.role) {
      case "admin":
        navigate("/");
        break;

      case "analyst":
        navigate("/customer");
        break;

      case "viewer":
        navigate("/executive");
        break;

      default:
        navigate("/");
    }
  } catch (err) {
    console.error("LOGIN ERROR:", err);

    if (err.response) {
      console.error("Status:", err.response.status);
      console.error("Data:", err.response.data);
    } else {
      console.error("Request URL:", `${API}/login`);
    }

    alert("Unable to connect to the server.");
  }
};
  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        background: "#020617"
      }}
    >
      <div
        style={{
          width: 400,
          background: "#111827",
          padding: 30,
          borderRadius: 18
        }}
      >
        <h2 style={{ color: "#00ffc8" }}>
          SafeChat AI SOC
        </h2>

        <input
          placeholder="Username"
          value={username}
          onChange={(e)=>setUsername(e.target.value)}
          style={{
            width:"100%",
            marginTop:20,
            padding:12
          }}
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e)=>setPassword(e.target.value)}
          style={{
            width:"100%",
            marginTop:15,
            padding:12
          }}
        />

        <button
          onClick={login}
          style={{
            width:"100%",
            marginTop:20,
            padding:12,
            background:"#00ffc8",
            border:"none",
            fontWeight:"bold",
            cursor:"pointer"
          }}
        >
          Login
        </button>
      </div>
    </div>
  );
}
