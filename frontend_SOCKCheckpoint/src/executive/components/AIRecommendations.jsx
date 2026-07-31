import "./AIRecommendations.css";

export default function AIRecommendations({
    recommendations = []
}) {

    return (

        <section className="ai-recommendations">

            <h2>🧠 AI Recommendations</h2>

            {recommendations.map((item,index)=>(

                <div
                    className={`recommendation ${item.priority.toLowerCase()}`}
                    key={index}
                >

                    <h3>{item.title}</h3>

                    <strong>{item.priority}</strong>

                    <p>{item.action}</p>

                </div>

            ))}

        </section>

    );

}