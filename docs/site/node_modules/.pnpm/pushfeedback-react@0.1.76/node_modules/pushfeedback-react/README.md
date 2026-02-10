# pushfeedback-react

Feedback widget for React.

## Prerequisites

Before proceeding, ensure you have:

- A [PushFeedback account](https://app.pushfeedback.com/accounts/signup/).
- A [project](https://docs.pushfeedback.com/#2-create-a-project) set up in your PushFeedback dashboard. 
- A React application with Node.js installed.

## Installation

1. Open your terminal or command prompt.
2. Navigate to your project's root directory:

    ```bash
    cd path/to/your/project
    ```

    Replace `path/to/your/project` with the actual path to your project directory.

3. Install PushFeedback by running:

    ```bash
    npm install pushfeedback-react
    ```

    > **INFO**: If you're using yarn, use `yarn add pushfeedback-react` instead.

1. In the main component where you want the feedback button to appear (commonly `src/App.js`), import and embed the PushFeedback button:

    ```jsx
    import React, { useEffect } from 'react';
    import { FeedbackButton } from 'pushfeedback-react';
    import { defineCustomElements } from 'pushfeedback/loader';
    import 'pushfeedback/dist/pushfeedback/pushfeedback.css';

    function App() {
        
        useEffect(() => {
            if (typeof window !== 'undefined') {
            defineCustomElements(window);
            }
        }, []);

        return (
            <div className="App">
                {/* Other components and content */}
                <FeedbackButton project="<YOUR_PROJECT_ID>" button-position="bottom-right" modal-position="bottom-right" button-style="light">Feedback</FeedbackButton>
            </div>
        );
    }

    export default App;
    ```

    Replace `<YOUR_PROJECT_ID>` with your project's ID from the PushFeedback dashboard.

5. After compiling your application, the feedback button should be visible and functional on your site.

## Configuration

For further customization and to explore additional features, refer to the [Configuration section](https://docs.pushfeedback.com/category/configuration).

## Support

Need assistance? [Contact us](https://docs.pushfeedback.com/support) for help.

## License

Copyright (c) 2023 PushFeedback

Licensed under the [MIT License](LICENSE.md).
