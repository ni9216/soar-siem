import { Component } from 'react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false,
      error: null,
      errorInfo: null
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({
      error,
      errorInfo
    });
    
    // Log error for debugging
    console.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: '100vh',
            background: 'linear-gradient(135deg, #020617 0%, #0f172a 100%)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            padding: 20,
            fontFamily: 'Inter, system-ui, sans-serif',
          }}
        >
          <div
            style={{
              maxWidth: 600,
              background: '#0f172a',
              border: '2px solid #ef4444',
              borderRadius: 24,
              padding: 36,
              boxShadow: '0 24px 80px rgba(0, 0, 0, 0.25)',
            }}
          >
            <div style={{ textAlign: 'center', marginBottom: 24 }}>
              <h1
                style={{
                  color: '#ef4444',
                  marginBottom: 12,
                  fontSize: 32,
                }}
              >
                ⚠️ Something Went Wrong
              </h1>
              <p style={{ color: '#94a3b8', margin: 0 }}>
                We encountered an unexpected error. Please try refreshing the page.
              </p>
            </div>

            {this.state.error && (
              <div
                style={{
                  background: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: 12,
                  padding: 16,
                  marginBottom: 24,
                  maxHeight: 200,
                  overflow: 'auto',
                }}
              >
                <p style={{ color: '#fca5a5', margin: '0 0 8px 0', fontSize: 12 }}>
                  <strong>Error Details:</strong>
                </p>
                <code
                  style={{
                    color: '#cbd5e1',
                    fontSize: 11,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {this.state.error.toString()}
                </code>
              </div>
            )}

            <div style={{ display: 'flex', gap: 12 }}>
              <button
                onClick={() => window.location.reload()}
                style={{
                  flex: 1,
                  padding: 14,
                  background: '#22c55e',
                  color: 'white',
                  border: 'none',
                  borderRadius: 12,
                  fontSize: 15,
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'background 0.2s',
                }}
                onMouseOver={(e) => e.target.style.background = '#16a34a'}
                onMouseOut={(e) => e.target.style.background = '#22c55e'}
              >
                Refresh Page
              </button>
              <button
                onClick={() => window.location.href = '/'}
                style={{
                  flex: 1,
                  padding: 14,
                  background: '#1e293b',
                  color: '#22c55e',
                  border: '1px solid #22c55e',
                  borderRadius: 12,
                  fontSize: 15,
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
                onMouseOver={(e) => {
                  e.target.style.background = '#0f172a';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = '#1e293b';
                }}
              >
                Go Home
              </button>
            </div>

            <p style={{ color: '#64748b', fontSize: 12, marginTop: 24, textAlign: 'center' }}>
              If this problem persists, please contact your administrator with the error details above.
            </p>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
