'use client';

import { useEffect, useState } from 'react';
import Image from 'next/image';

interface LoaderProps {
  onComplete?: () => void;
}

export default function Loader({ onComplete }: LoaderProps) {
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(false);
      setTimeout(() => {
        onComplete?.();
      }, 500); // Wait for fade out animation
    }, 2000); // Show loader for 2 seconds

    return () => clearTimeout(timer);
  }, [onComplete]);

  return (
    <div className={`loader-overlay ${!isVisible ? 'fade-out' : ''}`}>
      <div className="text-center">
        <Image
          src="/logo.png"
          alt="NadaLabs Logo"
          width={120}
          height={120}
          className="loader-logo mx-auto mb-4"
        />
        <div className="w-12 h-1 bg-gradient-to-r from-yellow-400 to-orange-400 rounded-full mx-auto">
          <div className="w-full h-full bg-gradient-to-r from-yellow-400 to-orange-400 rounded-full animate-pulse"></div>
        </div>
      </div>
    </div>
  );
}
