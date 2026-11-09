"use client";

import {
    motion,
    useTransform,
    useReducedMotion,
    useMotionValue,
    useSpring,
    MotionValue,
} from "framer-motion";
import { useEffect, useRef, useState } from "react";

// Curated for uKey: The 8-Layer Hardware Cryptographic Tunnel
const UKEY_TUNNEL_CARDS = [
    {
        src: "https://images.unsplash.com/photo-1629654297299-c8506221ca97?auto=format&fit=crop&w=800&q=80",
        title: "01 // Linux Terminal",
        subtitle: "OpenSSH ecdsa-sk & Git Sign",
    },
    {
        src: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=800&q=80",
        title: "02 // /dev/uhid Kernel",
        subtitle: "Virtual USB HID Descriptor",
    },
    {
        src: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=800&q=80",
        title: "03 // CTAPHID Wire",
        subtitle: "64-Byte Packet Framing",
    },
    {
        src: "https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=800&q=80",
        title: "04 // Canonical CBOR",
        subtitle: "CTAP2.1 Assertion Parser",
    },
    {
        src: "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=800&q=80",
        title: "05 // Local Loopback",
        subtitle: "adb reverse / Local TLS",
    },
    {
        src: "https://images.unsplash.com/photo-1607604276583-eef5d076aa5f?auto=format&fit=crop&w=800&q=80",
        title: "06 // Android Keystore",
        subtitle: "setUserAuthRequired(true)",
    },
    {
        src: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=800&q=80",
        title: "07 // Biometric Gate",
        subtitle: "Class 3 Hardware Fingerprint",
    },
    {
        src: "https://images.unsplash.com/photo-1519389950473-47ba0277781c?auto=format&fit=crop&w=800&q=80",
        title: "08 // StrongBox Silicon",
        subtitle: "Titan M2 / Knox EAL5+ Die",
    },
];

interface TunnelCardData {
    item: { src: string; title: string; subtitle?: string };
    angleCos: number;
    angleSin: number;
    radiusFactorX: number;
    radiusFactorY: number;
    rotationZ: number;
    index: number;
}

const TUNNEL_CARDS: TunnelCardData[] = UKEY_TUNNEL_CARDS.map((item, i) => {
    const goldenAngle = i * 137.5 * (Math.PI / 180);
    const radiusFactorX = 0.28 + (i % 3) * 0.08;
    const radiusFactorY = 0.26 + (i % 2) * 0.09;

    return {
        item,
        angleCos: Math.cos(goldenAngle),
        angleSin: Math.sin(goldenAngle),
        radiusFactorX,
        radiusFactorY,
        rotationZ: (i % 2 === 0 ? 1 : -1) * (3 + (i % 5) * 2),
        index: i,
    };
});

const SPRING_CONFIG = { stiffness: 60, damping: 25, mass: 0.5 };

interface StageDimensions {
    width: number;
    height: number;
    isMobile: boolean;
}

function useCameraParallax(enabled: boolean) {
    const rawX = useMotionValue(0);
    const rawY = useMotionValue(0);
    const x = useSpring(rawX, SPRING_CONFIG);
    const y = useSpring(rawY, SPRING_CONFIG);

    useEffect(() => {
        if (!enabled) return;
        const onMove = (e: PointerEvent) => {
            rawX.set((e.clientX / window.innerWidth - 0.5) * 2);
            rawY.set((e.clientY / window.innerHeight - 0.5) * 2);
        };
        window.addEventListener("pointermove", onMove, { passive: true });
        return () => window.removeEventListener("pointermove", onMove);
    }, [enabled, rawX, rawY]);

    return { x, y };
}

interface TunnelCardProps {
    card: TunnelCardData;
    progress: MotionValue<number>;
    pointer: { x: MotionValue<number>; y: MotionValue<number> };
    total: number;
    stage: StageDimensions;
}

function TunnelCard({ card, progress, pointer, total, stage }: TunnelCardProps) {
    const staggerSpan = 0.55;
    const start = (card.index / total) * (1 - staggerSpan);
    const end = start + staggerSpan;

    const localProgress = useTransform(progress, [start, end], [0, 1]);

    const farZ = stage.isMobile ? -1200 : -1700;
    const nearZ = stage.isMobile ? 350 : 500;
    const z = useTransform(localProgress, [0, 1], [farZ, nearZ]);

    const opacity = useTransform(localProgress, [0, 0.18, 0.82, 0.98], [0, 1, 1, 0]);

    const cardWidth = stage.isMobile
        ? Math.max(140, Math.min(190, stage.width * 0.38))
        : Math.max(200, Math.min(290, stage.width * 0.19));

    const baseX = card.angleCos * (stage.width * card.radiusFactorX);
    const baseY = card.angleSin * (stage.height * card.radiusFactorY);
    const panStrength = stage.isMobile ? 20 : 45;

    const transform = useTransform(
        [z, pointer.x, pointer.y],
        ([currZ, px, py]: number[]) => {
            const offsetX = baseX - px * panStrength;
            const offsetY = baseY - py * panStrength;
            return `translate3d(calc(-50% + ${offsetX}px), calc(-50% + ${offsetY}px), ${currZ}px) rotateZ(${card.rotationZ}deg)`;
        }
    );

    return (
        <motion.div
            style={{
                width: cardWidth,
                transform,
                opacity,
                zIndex: card.index + 1,
            }}
            className="pointer-events-auto absolute left-1/2 top-1/2 aspect-[4/5] will-change-transform select-none cursor-pointer"
        >
            <div className="group relative h-full w-full overflow-hidden rounded-2xl bg-neutral-900 border border-white/10 shadow-2xl shadow-black/80 transition-all duration-500 hover:border-emerald-500/60 hover:shadow-emerald-500/20">
                <img
                    src={card.item.src}
                    alt={card.item.title}
                    draggable={false}
                    className="h-full w-full object-cover transition-transform duration-700 ease-out group-hover:scale-110 opacity-70 group-hover:opacity-90"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/95 via-black/40 to-transparent flex flex-col justify-end p-4 sm:p-5">
                    <span className="text-xs font-mono tracking-widest uppercase text-emerald-400 font-semibold drop-shadow-md">
                        {card.item.title}
                    </span>
                    {card.item.subtitle && (
                        <span className="text-[11px] font-sans text-neutral-300 mt-1">
                            {card.item.subtitle}
                        </span>
                    )}
                </div>
            </div>
        </motion.div>
    );
}

export default function PerspectiveTunnelHero() {
    const containerRef = useRef<HTMLDivElement>(null);
    const reduce = useReducedMotion();

    const [stage, setStage] = useState<StageDimensions>({
        width: 1440,
        height: 900,
        isMobile: false,
    });

    useEffect(() => {
        const updateDimensions = () => {
            setStage({
                width: window.innerWidth,
                height: window.innerHeight,
                isMobile: window.innerWidth < 768,
            });
        };

        updateDimensions();
        window.addEventListener("resize", updateDimensions);
        return () => window.removeEventListener("resize", updateDimensions);
    }, []);

    const rawProgress = useMotionValue(0);
    const smoothProgress = useSpring(rawProgress, {
        stiffness: 80,
        damping: 30,
        restDelta: 0.0001,
    });

    useEffect(() => {
        const el = containerRef.current;
        if (!el) return;

        const handleWheel = (e: WheelEvent) => {
            e.preventDefault();
            const current = rawProgress.get();
            const delta = e.deltaY * 0.0008;
            const next = Math.min(1, Math.max(0, current + delta));
            rawProgress.set(next);
        };

        el.addEventListener("wheel", handleWheel, { passive: false });
        return () => el.removeEventListener("wheel", handleWheel);
    }, [rawProgress]);

    const pointer = useCameraParallax(!reduce);

    const titleScale = useTransform(smoothProgress, [0, 0.5, 1], [0.8, 1, 1.25]);
    const titleOpacity = useTransform(smoothProgress, [0, 0.12, 0.85, 1], [0.35, 1, 1, 0]);
    const promptOpacity = useTransform(smoothProgress, [0, 0.12], [1, 0]);

    return (
        <div
            ref={containerRef}
            className="relative h-[100svh] w-screen overflow-hidden bg-[#090D16] text-white select-none flex items-center justify-center"
            style={{
                perspective: stage.isMobile ? "900px" : "1200px",
                transformStyle: "preserve-3d",
            }}
        >
            {/* Background Grid & Silicon Glow */}
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:28px_28px] opacity-40" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(16,185,129,0.12)_0%,transparent_70%)]" />

            {/* Depth Ring Guides */}
            <div className="pointer-events-none absolute h-[48vmin] w-[48vmin] rounded-full border border-emerald-500/15" />
            <div className="pointer-events-none absolute h-[76vmin] w-[76vmin] rounded-full border border-dashed border-white/10" />

            {/* Central Anchor Typography */}
            <motion.div
                style={{ scale: titleScale, opacity: titleOpacity }}
                className="pointer-events-none z-0 flex flex-col items-center text-center px-6 max-w-2xl"
            >
                <p className="text-xs font-mono uppercase tracking-[0.4em] text-emerald-400 mb-3">
                    Cryptographic Tunnel // CTAP2
                </p>
                <h1 className="text-5xl sm:text-7xl md:text-8xl font-black tracking-tighter leading-[0.9] bg-gradient-to-b from-white via-neutral-200 to-neutral-500 bg-clip-text text-transparent uppercase font-['Archivo']">
                    INTO THE
                    <br />
                    SILICON.
                </h1>
                <p className="mt-4 max-w-[42ch] text-sm sm:text-base font-light text-neutral-400">
                    Scroll your mouse wheel or trackpad to fly through uKey's 8-layer hardware security corridor.
                </p>
            </motion.div>

            {/* Scroll Prompt */}
            <motion.div
                style={{ opacity: promptOpacity }}
                className="pointer-events-none absolute bottom-8 z-20 flex flex-col items-center gap-2 text-xs font-mono uppercase tracking-[0.3em] text-neutral-400"
            >
                <span>Scroll to Traverse</span>
                <div className="h-6 w-px bg-gradient-to-b from-emerald-500 to-transparent" />
            </motion.div>

            {/* 3D Z-Space Corridor Plane */}
            <div
                className="absolute inset-0 pointer-events-none"
                style={{ transformStyle: "preserve-3d" }}
            >
                {TUNNEL_CARDS.map((card, i) => (
                    <TunnelCard
                        key={i}
                        card={card}
                        progress={smoothProgress}
                        pointer={pointer}
                        total={TUNNEL_CARDS.length}
                        stage={stage}
                    />
                ))}
            </div>
        </div>
    );
}
