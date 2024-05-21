import { useEffect, useState } from 'react'
import './App.css'

function App() {
  const [data, setData] = useState<{ [key: string]: number }>({})
  const [packetSum, setPacketSum] = useState(0)

  useEffect(() => {
    setInterval(() => {
      fetch("http://localhost:8080/api/all").then(r => r.json().then(d =>
        setData(d)
      ))
    }, 1000)
  }, [])

  useEffect(() => {
    setPacketSum(Object.values(data).reduce((a, b) => { return a + b }, 0))
  }, [data])

  return (
    <div>
      <table>
        <tr>
          <th>Source IP</th>
          <th>Packet Count</th>
        </tr>
        {Object.keys(data).map(k => <tr key={k}><td>{k}</td> <td>{data[k]}</td></tr>)}
        <tr style={{ color: "lightgreen" }}><td>Total</td><td>{packetSum}</td></tr>
      </table>
    </div>
  )
}

export default App
