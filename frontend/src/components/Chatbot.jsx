import React, { useState } from 'react'
import './Chatbot.css'

const Chatbot = ({ defaultDestination }) => {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(false)

  const sendMessage = async () => {
    if (!input.trim()) return
    const userMsg = { role: 'user', text: input }
    setMessages((m) => [...m, userMsg])
    const payload = {
      message: input,
      destination: defaultDestination || null
    }
    setInput('')
    setLoading(true)
    try {
      const res = await fetch('/api/chat/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      const data = await res.json()
      const assistantText = data.assistant || 'Sorry, no response available.'
      setMessages((m) => [...m, { role: 'assistant', text: assistantText }])
    } catch (err) {
      setMessages((m) => [...m, { role: 'assistant', text: 'Error contacting chat service.' }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={`chatbot-root ${open ? 'open' : ''}`}>
      <div className="chatbot-toggle" onClick={() => setOpen(!open)}>
        {open ? '✕' : 'Chat'}
      </div>
      {open && (
        <div className="chatbot-window">
          <div className="chatbot-header">GeoSense Assistant</div>
          <div className="chatbot-body">
            {messages.length === 0 && (
              <div className="chatbot-empty">Ask me about beautiful places, safety, traffic, or construction near your destination.</div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`chatbot-message ${m.role}`}>
                <div className="chatbot-message-text">{m.text}</div>
              </div>
            ))}
          </div>
          <div className="chatbot-input">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about places, safety, traffic..."
              onKeyDown={(e) => { if (e.key === 'Enter') sendMessage() }}
            />
            <button onClick={sendMessage} disabled={loading}>{loading ? 'Sending...' : 'Send'}</button>
          </div>
        </div>
      )}
    </div>
  )
}

export default Chatbot
