import { Component } from 'react';
import { ShieldAlert, RotateCcw } from 'lucide-react';
import { Button } from '../ui/Button';

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-slate-50 p-6 dark:bg-obsidian-950">
          <div className="max-w-md rounded-lg border border-rose-200 bg-white p-6 text-center shadow-lg dark:border-rose-500/30 dark:bg-obsidian-900">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-rose-100 text-rose-600 dark:bg-rose-500/15 dark:text-rose-400">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <h1 className="mt-4 text-base font-semibold text-slate-900 dark:text-slate-100">
              Interface Error Encountered
            </h1>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {this.state.error?.message || 'An unexpected rendering error occurred.'}
            </p>
            <div className="mt-5 flex justify-center gap-2">
              <Button variant="outline" size="sm" onClick={this.handleReset}>
                <RotateCcw className="h-3.5 w-3.5" />
                Try Again
              </Button>
              <Button size="sm" onClick={() => window.location.assign('/')}>
                Reload Console
              </Button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
