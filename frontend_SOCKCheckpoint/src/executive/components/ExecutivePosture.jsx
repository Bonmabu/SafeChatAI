import React, {useEffect, useState} from "react";
import axios from "axios";


export default function ExecutivePosture(){

    const [status,setStatus] = useState(null);


    async function load(){

        try{

            const res =
            await axios.get(
            "http://127.0.0.1:8000/executive/posture"
            );

            setStatus(res.data);

        }
        catch(err){

            console.log(err);

        }

    }


    useEffect(()=>{

        load();

        const timer =
        setInterval(load,3000);


        return ()=>clearInterval(timer);

    },[]);



    if(!status)
        return null;


    return (

        <div className="executive-posture">

            <h2>
            🛡 Executive Security Posture
            </h2>


            <h1>
            {status.posture}
            </h1>


            <p>
            Risk:
            {" "}
            {status.risk_level}
            </p>


            <small>
            {status.reason}
            </small>


        </div>

    )

}