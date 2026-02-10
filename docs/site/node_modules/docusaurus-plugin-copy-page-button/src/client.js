import React from "react";
import { createRoot } from "react-dom/client";
import CopyPageButton from "./CopyPageButton";
import ExecutionEnvironment from '@docusaurus/ExecutionEnvironment';

// Only run in browser environment
if (ExecutionEnvironment.canUseDOM) {
  let root = null;
  let lastUrl = location.href;
  let recheckInterval = null;
  let injectionAttempts = 0;

  const getPluginOptions = () => {
    return (typeof window !== "undefined" && window.__COPY_PAGE_BUTTON_OPTIONS__) || {};
  };

  // Fallback injection for pages without TOC
  const injectToFallbackLocation = () => {
    // Look for main article content area
    const articleContent = 
      document.querySelector("article") ||
      document.querySelector(".markdown") ||
      document.querySelector('[class*="docItemContainer"]') ||
      document.querySelector('.theme-doc-markdown') ||
      document.querySelector('main');

    if (!articleContent) {
      return; // No suitable container found
    }

    let container = document.getElementById("copy-page-button-container");
    if (container && articleContent.contains(container)) {
      return; // Already properly attached
    }

    if (container) {
      cleanup();
    }

    container = document.createElement("div");
    container.id = "copy-page-button-container";

    // Apply custom positioning styles to the container if provided
    const pluginOptions = getPluginOptions();
    const customStyles = pluginOptions.customStyles || {};
    const buttonStyles = customStyles.button?.style || {};
    
    // Check if button config has positioning styles that should be applied to container
    const positioningProps = ['position', 'top', 'right', 'bottom', 'left', 'zIndex', 'transform'];
    positioningProps.forEach(prop => {
      if (buttonStyles[prop] !== undefined) {
        container.style[prop] = buttonStyles[prop];
      }
    });
    
    // For fallback injection, use fixed positioning in top-right of viewport if no custom positioning
    const hasCustomPositioning = positioningProps.some(prop => buttonStyles[prop] !== undefined);
    if (!hasCustomPositioning) {
      container.style.position = 'fixed';
      container.style.top = '80px';
      container.style.right = '20px';
      container.style.zIndex = '1000';
    }
    
    // Also apply container-specific styles
    const containerStyles = customStyles.container?.style || {};
    Object.assign(container.style, containerStyles);

    articleContent.insertBefore(container, articleContent.firstChild);

    if (root) {
      try {
        root.unmount();
      } catch (e) {
        // Silent cleanup
      }
    }
    root = createRoot(container);

    const renderOptions = getPluginOptions();
    root.render(React.createElement(CopyPageButton, {
      customStyles: renderOptions.customStyles,
      enabledActions: renderOptions.enabledActions
    }));
  };

  // Fast injection for navigation (when sidebar already exists)
  const fastInjectCopyPageButton = () => {
    const sidebar =
      document.querySelector(".theme-doc-toc-desktop") ||
      document.querySelector(".table-of-contents") ||
      document.querySelector('[class*="tableOfContents"]') ||
      document.querySelector('[class*="toc"]');

    if (!sidebar) {
      // If no sidebar, try fallback injection to main content area
      injectToFallbackLocation();
      return;
    }

    let container = document.getElementById("copy-page-button-container");
    if (container && sidebar.contains(container)) {
      return; // Already properly attached
    }

    if (container) {
      cleanup();
    }

    container = document.createElement("div");
    container.id = "copy-page-button-container";

    // Apply custom positioning styles to the container if provided
    const pluginOptions = getPluginOptions();
    const customStyles = pluginOptions.customStyles || {};
    const buttonStyles = customStyles.button?.style || {};
    
    // Check if button config has positioning styles that should be applied to container
    const positioningProps = ['position', 'top', 'right', 'bottom', 'left', 'zIndex', 'transform'];
    positioningProps.forEach(prop => {
      if (buttonStyles[prop] !== undefined) {
        container.style[prop] = buttonStyles[prop];
      }
    });
    
    // Also apply container-specific styles
    const containerStyles = customStyles.container?.style || {};
    Object.assign(container.style, containerStyles);

    sidebar.insertBefore(container, sidebar.firstChild);

    if (root) {
      try {
        root.unmount();
      } catch (e) {
        // Silent cleanup
      }
    }
    root = createRoot(container);

    const renderOptions = getPluginOptions();
    root.render(React.createElement(CopyPageButton, {
      customStyles: renderOptions.customStyles,
      enabledActions: renderOptions.enabledActions
    }));
  };

  // Reliable injection for page refresh/initial load (when DOM might not be ready)
  const reliableInjectCopyPageButton = () => {
    injectionAttempts++;
    
    const sidebar =
      document.querySelector(".theme-doc-toc-desktop") ||
      document.querySelector(".table-of-contents") ||
      document.querySelector('[class*="tableOfContents"]') ||
      document.querySelector('[class*="toc"]');

    if (!sidebar) {
      // Try fallback injection to main content area
      const articleContent = 
        document.querySelector("article") ||
        document.querySelector(".markdown") ||
        document.querySelector('[class*="docItemContainer"]') ||
        document.querySelector('.theme-doc-markdown') ||
        document.querySelector('main');
        
      if (articleContent) {
        injectToFallbackLocation();
        injectionAttempts = 0; // Reset counter on success
        return;
      } else if (injectionAttempts < 30) { // Try for 3 seconds max
        setTimeout(reliableInjectCopyPageButton, 100);
      }
      return;
    }

    let container = document.getElementById("copy-page-button-container");
    if (container && sidebar.contains(container)) {
      injectionAttempts = 0; // Reset counter on success
      return; // Already properly attached
    }

    if (container) {
      cleanup();
    }

    container = document.createElement("div");
    container.id = "copy-page-button-container";

    // Apply custom positioning styles to the container if provided
    const pluginOptions = getPluginOptions();
    const customStyles = pluginOptions.customStyles || {};
    const buttonStyles = customStyles.button?.style || {};
    
    // Check if button config has positioning styles that should be applied to container
    const positioningProps = ['position', 'top', 'right', 'bottom', 'left', 'zIndex', 'transform'];
    positioningProps.forEach(prop => {
      if (buttonStyles[prop] !== undefined) {
        container.style[prop] = buttonStyles[prop];
      }
    });
    
    // Also apply container-specific styles
    const containerStyles = customStyles.container?.style || {};
    Object.assign(container.style, containerStyles);

    sidebar.insertBefore(container, sidebar.firstChild);

    if (root) {
      try {
        root.unmount();
      } catch (e) {
        // Silent cleanup
      }
    }
    root = createRoot(container);

    const renderOptions = getPluginOptions();
    root.render(React.createElement(CopyPageButton, {
      customStyles: renderOptions.customStyles,
      enabledActions: renderOptions.enabledActions
    }));

    // Reset injection attempts on successful injection
    injectionAttempts = 0;
    
    // Clear any existing recheck interval since button is now injected
    if (recheckInterval) {
      clearInterval(recheckInterval);
      recheckInterval = null;
    }
  };

  const cleanup = () => {
    const container = document.getElementById("copy-page-button-container");
    if (container) {
      if (root) {
        try {
          root.unmount();
        } catch (e) {
          // Silent cleanup
        }
      }
      container.remove();
    }
  };

  // Fast route change handler (navigation within SPA)
  const handleRouteChange = () => {
    // Check if button is properly attached before cleaning up
    const container = document.getElementById("copy-page-button-container");
    const sidebar =
      document.querySelector(".theme-doc-toc-desktop") ||
      document.querySelector(".table-of-contents") ||
      document.querySelector('[class*="tableOfContents"]') ||
      document.querySelector('[class*="toc"]');
    
    // Check if button is attached to sidebar or fallback location
    const articleContent = 
      document.querySelector("article") ||
      document.querySelector(".markdown") ||
      document.querySelector('[class*="docItemContainer"]') ||
      document.querySelector('.theme-doc-markdown') ||
      document.querySelector('main');
    
    const buttonProperlyAttached = container && (
      (sidebar && sidebar.contains(container)) ||
      (articleContent && articleContent.contains(container))
    );
    
    // Only cleanup and re-inject if button is not properly attached
    if (!buttonProperlyAttached) {
      cleanup();
      
      // Clear any existing recheck interval
      if (recheckInterval) {
        clearInterval(recheckInterval);
        recheckInterval = null;
      }
      
      // Use fast injection for navigation since DOM is already stable
      if (window.innerWidth <= 996) {
        // Mobile/tablet: small delay for sidebar re-rendering
        setTimeout(fastInjectCopyPageButton, 50);
      } else {
        // Desktop: immediate injection
        fastInjectCopyPageButton();
      }
    }
  };

  // Reliable initialization for page refresh/initial load
  const initializeButton = () => {
    // Reset injection attempts to ensure button can be re-injected after refresh
    injectionAttempts = 0;
    
    // Multi-strategy initialization for page refresh
    const attemptInjection = () => {
      // Strategy 1: Try immediate injection
      const sidebar = document.querySelector(".theme-doc-toc-desktop") ||
        document.querySelector(".table-of-contents") ||
        document.querySelector('[class*="tableOfContents"]') ||
        document.querySelector('[class*="toc"]');
        
      const articleContent = 
        document.querySelector("article") ||
        document.querySelector(".markdown") ||
        document.querySelector('[class*="docItemContainer"]') ||
        document.querySelector('.theme-doc-markdown') ||
        document.querySelector('main');
        
      if (sidebar || articleContent) {
        // Suitable container found - inject with reasonable delay
        setTimeout(reliableInjectCopyPageButton, 100);
      } else {
        // Strategy 2: Wait for Docusaurus to fully load
        if (window.docusaurus || document.readyState === 'complete') {
          setTimeout(() => {
            reliableInjectCopyPageButton();
            // Start backup periodic checking
            startPeriodicCheck();
          }, 300);
        } else {
          // Strategy 3: Wait for framework readiness
          setTimeout(() => {
            reliableInjectCopyPageButton();
            startPeriodicCheck();
          }, 500);
        }
      }
    };
    
    // Use appropriate timing based on document state
    if (document.readyState === 'complete') {
      attemptInjection();
    } else {
      // Wait for document to be complete
      const waitForComplete = () => {
        if (document.readyState === 'complete' || window.docusaurus) {
          setTimeout(attemptInjection, 100);
        } else {
          setTimeout(waitForComplete, 100);
        }
      };
      waitForComplete();
    }
  };

  // Periodic check - only for initial page load issues
  const startPeriodicCheck = () => {
    let recheckCount = 0;
    const maxRechecks = 30; // 15 seconds total - increased for slower loading pages
    
    // Clear any existing interval
    if (recheckInterval) {
      clearInterval(recheckInterval);
    }
    
    recheckInterval = setInterval(() => {
      recheckCount++;
      const container = document.getElementById("copy-page-button-container");
      const sidebar = document.querySelector(".theme-doc-toc-desktop") ||
        document.querySelector(".table-of-contents") ||
        document.querySelector('[class*="tableOfContents"]') ||
        document.querySelector('[class*="toc"]');
      
      const articleContent = 
        document.querySelector("article") ||
        document.querySelector(".markdown") ||
        document.querySelector('[class*="docItemContainer"]') ||
        document.querySelector('.theme-doc-markdown') ||
        document.querySelector('main');
      
      const needsInjection = (sidebar || articleContent) && (!container || 
        (!sidebar || !sidebar.contains(container)) && 
        (!articleContent || !articleContent.contains(container)));
      
      if (needsInjection) {
        // Log only if we're having to retry (indicates potential issue)
        if (recheckCount > 3) {
          console.log('[Copy Button] Re-injecting after', recheckCount * 0.5, 'seconds');
        }
        reliableInjectCopyPageButton();
      }
      
      const buttonProperlyAttached = container && (
        (sidebar && sidebar.contains(container)) ||
        (articleContent && articleContent.contains(container))
      );
      
      if (recheckCount >= maxRechecks || buttonProperlyAttached) {
        clearInterval(recheckInterval);
        recheckInterval = null;
      }
    }, 500);
  };

  // Initialize when DOM is ready (only for page refresh/initial load)
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(initializeButton, 100);
    });
  } else {
    setTimeout(initializeButton, 100);
  }

  // Force re-injection on page visibility change (helps with tab switching and refreshes)
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      setTimeout(() => {
        const container = document.getElementById("copy-page-button-container");
        const sidebar = document.querySelector(".theme-doc-toc-desktop") ||
          document.querySelector(".table-of-contents") ||
          document.querySelector('[class*="tableOfContents"]') ||
          document.querySelector('[class*="toc"]');
        
        const articleContent = 
          document.querySelector("article") ||
          document.querySelector(".markdown") ||
          document.querySelector('[class*="docItemContainer"]') ||
          document.querySelector('.theme-doc-markdown') ||
          document.querySelector('main');
        
        const needsInjection = (sidebar || articleContent) && (!container || 
          (!sidebar || !sidebar.contains(container)) && 
          (!articleContent || !articleContent.contains(container)));
        
        if (needsInjection) {
          reliableInjectCopyPageButton();
        }
      }, 200);
    }
  });

  // Handle responsive layout changes
  window.addEventListener("resize", () => {
    setTimeout(() => {
      const container = document.getElementById("copy-page-button-container");
      const sidebar =
        document.querySelector(".theme-doc-toc-desktop") ||
        document.querySelector(".table-of-contents") ||
        document.querySelector('[class*="tableOfContents"]') ||
        document.querySelector('[class*="toc"]');

      const articleContent = 
        document.querySelector("article") ||
        document.querySelector(".markdown") ||
        document.querySelector('[class*="docItemContainer"]') ||
        document.querySelector('.theme-doc-markdown') ||
        document.querySelector('main');

      const sidebarVisible =
        sidebar &&
        sidebar.offsetWidth > 0 &&
        sidebar.offsetHeight > 0 &&
        window.getComputedStyle(sidebar).display !== "none";

      const buttonProperlyAttached = container && (
        (sidebar && sidebar.contains(container)) ||
        (articleContent && articleContent.contains(container))
      );

      if ((sidebarVisible || articleContent) && !buttonProperlyAttached) {
        cleanup();
        fastInjectCopyPageButton(); // Use fast injection for resize
      } else if (!sidebarVisible && !articleContent && buttonProperlyAttached) {
        cleanup();
      }
    }, 300);
  });

  // Handle browser navigation
  window.addEventListener("popstate", handleRouteChange);

  // Handle Docusaurus route changes
  if (typeof window !== "undefined" && window.docusaurus) {
    document.addEventListener("docusaurus-route-update", handleRouteChange);
  }

  // Targeted URL change detection for SPA routing
  const checkUrlChange = () => {
    if (location.href !== lastUrl) {
      const currentPathname = location.pathname;
      const lastPathname = new URL(lastUrl).pathname;
      
      // Only trigger route change for actual page changes, not hash/query changes
      if (currentPathname !== lastPathname) {
        lastUrl = location.href;
        handleRouteChange(); // Use fast route change handler
      } else {
        // Just update the URL without triggering re-injection
        lastUrl = location.href;
      }
    }
  };

  // Check for URL changes - keep this for SPA navigation
  setInterval(checkUrlChange, 100);

  // Also intercept pushState/replaceState for immediate detection
  const originalPushState = history.pushState;
  const originalReplaceState = history.replaceState;

  history.pushState = function (...args) {
    originalPushState.apply(this, args);
    setTimeout(checkUrlChange, 0);
  };

  history.replaceState = function (...args) {
    originalReplaceState.apply(this, args);
    setTimeout(checkUrlChange, 0);
  };
}
