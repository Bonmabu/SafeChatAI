import "./CampaignDashboard.css";
import { useEffect, useState } from "react";

const API =
    import.meta.env.VITE_API_BASE ||
    "http://127.0.0.1:8000";

export default function CampaignDashboard() {

    const [campaigns, setCampaigns] = useState([]);

    async function loadCampaigns() {

        try {

            const res = await fetch(`${API}/campaigns`);
            const data = await res.json();

            setCampaigns(data);

        } catch (err) {

            console.error(err);

        }

    }

    useEffect(() => {

        loadCampaigns();

        const timer = setInterval(loadCampaigns, 5000);

        return () => clearInterval(timer);

    }, []);

    return (

        <div className="executive-card">

            <h3>🎯 Active Campaign Intelligence</h3>

            <table className="campaign-table">

                <thead>

                    <tr>

                        <th>ID</th>
                        <th>Campaign</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Users</th>
                        <th>Hosts</th>
                        <th>IPs</th>
                        <th>Kill Chain</th>

                    </tr>

                </thead>

                <tbody>

                    {campaigns.map((c) => (

                        <tr key={c.id}>

                            <td>{c.id}</td>

                            <td>{c.campaign}</td>

                            <td>{c.severity}</td>

                            <td>{c.status}</td>

                            <td>{c.users.join(", ")}</td>

                            <td>{c.hosts.join(", ")}</td>

                            <td>{c.ips.join(", ")}</td>

                            <td>{c.kill_chain.join(" ➜ ")}</td>

                        </tr>

                    ))}

                </tbody>

            </table>

        </div>

    );

}