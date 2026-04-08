import React from 'react';

export default function Root({children}) {
  return (
    <>
      <a
        href="/llms.txt"
        style={{
          position: 'absolute',
          width: '1px',
          height: '1px',
          overflow: 'hidden',
          clip: 'rect(0,0,0,0)',
          whiteSpace: 'nowrap',
        }}
      >
        llms.txt
      </a>
      {children}
    </>
  );
}
