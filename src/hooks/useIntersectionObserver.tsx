'use client';

import { useEffect, useRef, useState } from 'react';

interface UseIntersectionObserverProps {
  threshold?: number;
  rootMargin?: string;
  triggerOnce?: boolean;
}

export function useIntersectionObserver({
  threshold = 0.15,
  rootMargin = '0px',
  triggerOnce = true,
}: UseIntersectionObserverProps = {}) {
  const [isIntersecting, setIsIntersecting] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsIntersecting(true);
          if (triggerOnce) {
            observer.unobserve(element);
          }
        } else if (!triggerOnce) {
          setIsIntersecting(false);
        }
      },
      { threshold, rootMargin }
    );

    observer.observe(element);

    return () => observer.disconnect();
  }, [threshold, rootMargin, triggerOnce]);

  return { ref, isIntersecting };
}

interface AnimatedSectionProps {
  children: React.ReactNode;
  animation?: 'fade-in-left' | 'fade-in-right' | 'fade-in-up' | 'fade-in-scale';
  delay?: number;
  className?: string;
}

export function AnimatedSection({ 
  children, 
  animation = 'fade-in-up', 
  delay = 0,
  className = '' 
}: AnimatedSectionProps) {
  const { ref, isIntersecting } = useIntersectionObserver({
    threshold: 0.15,
    rootMargin: '0px 0px -80px 0px',
  });

  const getInitialTransform = () => {
    switch (animation) {
      case 'fade-in-left':
        return 'translateX(-60px)';
      case 'fade-in-right':
        return 'translateX(60px)';
      case 'fade-in-scale':
        return 'scale(0.95)';
      default:
        return 'translateY(40px)';
    }
  };

  return (
    <div 
      ref={ref}
      className={`transition-all duration-1000 ease-out ${className} ${isIntersecting ? animation : ''}`}
      style={{ 
        animationDelay: isIntersecting ? `${delay}ms` : '0ms',
        opacity: isIntersecting ? 1 : 0,
        transform: isIntersecting ? 'none' : getInitialTransform()
      }}
    >
      {children}
    </div>
  );
}
