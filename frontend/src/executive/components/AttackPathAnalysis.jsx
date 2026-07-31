import "./AttackPathAnalysis.css";

export default function AttackPathAnalysis({ paths = [] }) {

    return (

        <section className="attack-path-panel">

            <h2>🛣 Attack Path Analysis</h2>

            {paths.map(path => (

                <div
                    className="attack-path-card"
                    key={path.id}
                >

                    <div className="attack-header">

                        <strong>
                            {path.risk}
                        </strong>

                        <span>
                            {path.probability}% Success
                        </span>

                    </div>

                    <div className="attack-flow">

                        {path.steps.map((step,index)=>(

                            <span key={index}>

                                {step}

                                {index < path.steps.length-1 &&
                                    " → "}

                            </span>

                        ))}

                    </div>

                    <div className="attack-impact">

                        Business Impact:
                        <strong>
                            {" "}{path.business_impact}
                        </strong>

                    </div>

                </div>

            ))}

        </section>

    );

}