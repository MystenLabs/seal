import React, { useState, useEffect } from 'react';
import SearchModal from '@site/src/components/Search/SearchModal';

export default function Root({children}) {
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    const handler = () => setSearchOpen(true);
    document.addEventListener('open-search-modal', handler);
    return () => document.removeEventListener('open-search-modal', handler);
  }, []);

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
      <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />
    </>
  );
}
