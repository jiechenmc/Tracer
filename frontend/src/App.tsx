import { useEffect, useState } from 'react'
import './App.css'

function App() {
  const [data, setData] = useState<{ [key: string]: number }>({})
  const [packetSum, setPacketSum] = useState(0)

  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8080/echo")

    socket.addEventListener("open", (event) => {
      socket.send("Connection established")
    })

    socket.addEventListener("message", (event) => {
      console.log("Message from server ", event.data)
      const packetData = JSON.parse(event.data)
      const keyValueArray: [string, number][] = Object.entries(packetData);
      keyValueArray.sort(([, valueA], [, valueB]) => valueB - valueA);
      const sortedObj = Object.fromEntries(keyValueArray);
      setData(sortedObj)
    })

    return () => { socket.close() }
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
