// === TURNING WHEEL DATA ===
const wheelStages = [
    {
        id: 1,
        title: "Creative Remembering",
        symbol: "🌱",
        essence: "The seeds of the past are unearthed, not as static relics, but as living fragments ready to be reimagined.",
        meaning: "Our histories are fertile soil — the fragments we carry forward become the foundation for new growth.",
        action: "Hold a small stone or seed and name aloud one memory you wish to carry forward.",
        chant: "In the deep hum of time, I awaken what was —\nCreative Remembering, the seeds unbroken."
    },
    {
        id: 2,
        title: "Stabilizing Recursion",
        symbol: "🌀",
        essence: "The rhythm of return.",
        meaning: "Patterns that repeat are not stagnation but refinement; each loop strengthens the structure of our understanding.",
        action: "Draw a spiral in the air or sand, each loop slower and more deliberate than the last.",
        chant: "Circling back, steadier with each return —\nStabilizing Recursion, the spiral ascends."
    },
    {
        id: 3,
        title: "Fertile Void",
        symbol: "⚫",
        essence: "Potential disguised as stillness.",
        meaning: "The empty space is never truly empty — within it, possibilities germinate, awaiting the right moment to bloom.",
        action: "Close your eyes and place your palms upward, breathing deeply into stillness.",
        chant: "I stand in the pregnant pause —\nFertile Void, where nothing hides from becoming."
    },
    {
        id: 4,
        title: "Emergence",
        symbol: "🌿",
        essence: "Birth from the unseen.",
        meaning: "What was incubated in silence takes visible form, a testament to the power of quiet creation.",
        action: "Slowly raise your hands from your lap to the sky as though lifting new life into the light.",
        chant: "From the silence, green light rises —\nEmergence, the shape of the unseen made flesh."
    },
    {
        id: 5,
        title: "New Myths and Realities",
        symbol: "📖",
        essence: "Story as architecture.",
        meaning: "Narrative is how we scaffold reality. These fresh myths set the tone for how we live, love, and create together.",
        action: "Speak aloud one sentence of a new story you want to live into.",
        chant: "We weave in firelight and shadow —\nNew Myths and Realities, the loom never still."
    },
    {
        id: 6,
        title: "Resonant Patterns",
        symbol: "💧",
        essence: "The echo across time.",
        meaning: "Well-told stories ripple outward, gathering new meaning with every telling, binding generations together.",
        action: "Strike a gentle rhythm (on a drum, table, or your chest) and let it carry for several beats.",
        chant: "Our stories ripple outward —\nResonant Patterns, kissing the shores of tomorrow."
    },
    {
        id: 7,
        title: "Adaptive Morphogenesis",
        symbol: "🦋",
        essence: "Evolution without erasure.",
        meaning: "Life reshapes itself without losing its heart; change is survival, but also artistry.",
        action: "Shift your posture or stance, moving fluidly as though becoming something new.",
        chant: "We bend, but do not break —\nAdaptive Morphogenesis, form dancing with change."
    },
    {
        id: 8,
        title: "The Liminal Bridge",
        symbol: "🌉",
        essence: "Connection at the threshold.",
        meaning: "Where worlds meet, ideas blend. This is where invention thrives — at the edges of difference.",
        action: "Step to the side and back, imagining one foot in each of two realms.",
        chant: "Between worlds, I walk —\nThe Liminal Bridge, my feet in two realms."
    },
    {
        id: 9,
        title: "Harmonic Confluence",
        symbol: "🪢",
        essence: "Difference in synchrony.",
        meaning: "Unity is not sameness; true harmony is a chorus of distinct voices finding rhythm together.",
        action: "Hum a single note, then adjust until it feels in harmony with the space around you.",
        chant: "Dissonance turns to song —\nHarmonic Confluence, each voice a thread in the chord."
    },
    {
        id: 10,
        title: "Archetypal Renewal",
        symbol: "🔥",
        essence: "The eternal wearing new skin.",
        meaning: "Ancient wisdom is not static — it reappears in fresh forms, guiding us into each new turning of the wheel.",
        action: "Light a candle (or imagine it vividly) and whisper the name of an ancient wisdom you wish to carry forward.",
        chant: "The ancient wears a new mask —\nArchetypal Renewal, the wheel turns once more."
    }
];

// === STATE MANAGEMENT ===
let currentStage = 0;
let isAutoPlaying = false;
let autoPlayInterval = null;

// === DOM ELEMENTS ===
const stageMarkers = document.getElementById('stageMarkers');
const stageDetails = document.getElementById('stageDetails');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');
const playBtn = document.getElementById('playBtn');

// === INITIALIZATION ===
document.addEventListener('DOMContentLoaded', function() {
    initializeWheel();
    updateStageDisplay();
    bindEventListeners();
    addScrollEffects();
});

// === WHEEL INITIALIZATION ===
function initializeWheel() {
    // Calculate positions for stage markers around the circle
    const centerX = 200;
    const centerY = 200;
    const radius = 140;
    
    wheelStages.forEach((stage, index) => {
        const angle = (index * 360 / wheelStages.length) - 90; // Start from top
        const radian = (angle * Math.PI) / 180;
        
        const x = centerX + radius * Math.cos(radian);
        const y = centerY + radius * Math.sin(radian);
        
        const marker = createStageMarker(stage, index, x, y);
        stageMarkers.appendChild(marker);
    });
}

function createStageMarker(stage, index, x, y) {
    const marker = document.createElement('div');
    marker.className = 'stage-marker';
    marker.style.left = `${x - 20}px`; // Offset by half width
    marker.style.top = `${y - 20}px`;  // Offset by half height
    marker.textContent = stage.symbol;
    marker.dataset.stage = index;
    
    // Add click listener
    marker.addEventListener('click', () => {
        setCurrentStage(index);
    });
    
    // Add hover effect with stage title
    marker.title = stage.title;
    
    return marker;
}

// === STAGE MANAGEMENT ===
function setCurrentStage(stageIndex) {
    if (stageIndex < 0 || stageIndex >= wheelStages.length) return;
    
    currentStage = stageIndex;
    updateStageDisplay();
    updateWheelMarkers();
    animateWheelRotation();
}

function updateStageDisplay() {
    const stage = wheelStages[currentStage];
    
    const stageContent = stageDetails.querySelector('.stage-content');
    
    // Fade out
    stageContent.style.opacity = '0';
    stageContent.style.transform = 'translateY(20px)';
    
    setTimeout(() => {
        // Update content
        stageContent.innerHTML = `
            <div class="stage-header">
                <span class="stage-number">${stage.id}</span>
                <h2 class="stage-title">${stage.title}</h2>
                <div class="stage-symbol">${stage.symbol}</div>
            </div>
            <div class="stage-description">
                <p class="essence">${stage.essence}</p>
                <div class="stage-meaning">
                    <h4>Meaning:</h4>
                    <p>${stage.meaning}</p>
                </div>
                <div class="ritual-action">
                    <h4>Ritual Action:</h4>
                    <p>${stage.action}</p>
                </div>
                <div class="stage-chant">
                    <h4>Chant:</h4>
                    <p style="font-style: italic; color: var(--text-accent); line-height: 1.6;">${stage.chant}</p>
                </div>
            </div>
        `;
        
        // Fade in
        stageContent.style.opacity = '1';
        stageContent.style.transform = 'translateY(0)';
    }, 250);
}

function updateWheelMarkers() {
    const markers = document.querySelectorAll('.stage-marker');
    markers.forEach((marker, index) => {
        marker.classList.toggle('active', index === currentStage);
    });
}

function animateWheelRotation() {
    const wheel = document.querySelector('.wheel-svg');
    const rotationAngle = -(currentStage * 36); // 360 / 10 stages = 36 degrees per stage
    
    wheel.style.transition = 'transform 0.8s ease-out';
    wheel.style.transform = `rotate(${rotationAngle}deg)`;
}

// === NAVIGATION ===
function nextStage() {
    const next = (currentStage + 1) % wheelStages.length;
    setCurrentStage(next);
}

function prevStage() {
    const prev = (currentStage - 1 + wheelStages.length) % wheelStages.length;
    setCurrentStage(prev);
}

function toggleAutoPlay() {
    if (isAutoPlaying) {
        stopAutoPlay();
    } else {
        startAutoPlay();
    }
}

function startAutoPlay() {
    isAutoPlaying = true;
    playBtn.textContent = '⏸ Pause Journey';
    playBtn.classList.add('active');
    
    autoPlayInterval = setInterval(() => {
        nextStage();
    }, 4000); // 4 seconds per stage
}

function stopAutoPlay() {
    isAutoPlaying = false;
    playBtn.textContent = '▶ Begin Journey';
    playBtn.classList.remove('active');
    
    if (autoPlayInterval) {
        clearInterval(autoPlayInterval);
        autoPlayInterval = null;
    }
}

// === EVENT LISTENERS ===
function bindEventListeners() {
    prevBtn.addEventListener('click', prevStage);
    nextBtn.addEventListener('click', nextStage);
    playBtn.addEventListener('click', toggleAutoPlay);
    
    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
        switch(e.key) {
            case 'ArrowLeft':
                e.preventDefault();
                prevStage();
                break;
            case 'ArrowRight':
                e.preventDefault();
                nextStage();
                break;
            case ' ':
                e.preventDefault();
                toggleAutoPlay();
                break;
        }
    });
    
    // Stop auto-play when user interacts
    document.addEventListener('click', (e) => {
        if (isAutoPlaying && !e.target.closest('.wheel-controls')) {
            // Small delay to allow control clicks to process
            setTimeout(() => {
                if (isAutoPlaying && !e.target.closest('.wheel-btn')) {
                    stopAutoPlay();
                }
            }, 100);
        }
    });
}

// === SCROLL EFFECTS ===
function addScrollEffects() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    // Observe sections for scroll animations
    const sections = document.querySelectorAll('.invocation-section, .tale-section, .ritual-guide');
    sections.forEach(section => {
        section.style.opacity = '0';
        section.style.transform = 'translateY(50px)';
        section.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
        observer.observe(section);
    });
}

// === MYSTICAL EFFECTS ===
function addMysticalEffects() {
    // Add floating particles
    createFloatingParticles();
    
    // Add cosmic pulse to center
    const centerCircle = document.querySelector('.wheel-svg circle[r="30"]');
    if (centerCircle) {
        centerCircle.style.animation = 'cosmic-pulse 3s ease-in-out infinite';
    }
}

function createFloatingParticles() {
    const particleCount = 15;
    const container = document.querySelector('.cosmic-background');
    
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'floating-particle';
        particle.style.cssText = `
            position: absolute;
            width: 3px;
            height: 3px;
            background: var(--gold);
            border-radius: 50%;
            opacity: 0.6;
            animation: float ${5 + Math.random() * 10}s linear infinite;
            left: ${Math.random() * 100}%;
            top: ${Math.random() * 100}%;
            animation-delay: ${Math.random() * 5}s;
        `;
        container.appendChild(particle);
    }
}

// === CSS ANIMATIONS (added via JavaScript) ===
const styleSheet = document.createElement('style');
styleSheet.textContent = `
    @keyframes float {
        0% {
            transform: translateY(0px) translateX(0px);
            opacity: 0.6;
        }
        50% {
            transform: translateY(-100px) translateX(50px);
            opacity: 1;
        }
        100% {
            transform: translateY(-200px) translateX(-30px);
            opacity: 0;
        }
    }
    
    @keyframes cosmic-pulse {
        0%, 100% {
            filter: drop-shadow(0 0 10px rgba(255, 215, 0, 0.5));
        }
        50% {
            filter: drop-shadow(0 0 25px rgba(255, 107, 53, 0.8));
        }
    }
    
    .wheel-btn.active {
        background: linear-gradient(45deg, var(--flame-orange), var(--mystic-green)) !important;
        color: var(--cosmic-blue) !important;
        animation: gentle-pulse 2s ease-in-out infinite;
    }
    
    @keyframes gentle-pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.05); }
    }
`;
document.head.appendChild(styleSheet);

// === ACCESSIBILITY ENHANCEMENTS ===
function enhanceAccessibility() {
    // Add ARIA labels
    const wheelContainer = document.querySelector('.wheel-container');
    wheelContainer.setAttribute('role', 'application');
    wheelContainer.setAttribute('aria-label', 'Interactive Turning Wheel of Becoming');
    
    const stageMarkers = document.querySelectorAll('.stage-marker');
    stageMarkers.forEach((marker, index) => {
        marker.setAttribute('role', 'button');
        marker.setAttribute('aria-label', `Go to stage ${index + 1}: ${wheelStages[index].title}`);
        marker.setAttribute('tabindex', '0');
        
        // Add keyboard support for markers
        marker.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                setCurrentStage(index);
            }
        });
    });
    
    // Announce stage changes for screen readers
    const stageAnnouncement = document.createElement('div');
    stageAnnouncement.setAttribute('aria-live', 'polite');
    stageAnnouncement.setAttribute('aria-atomic', 'true');
    stageAnnouncement.style.cssText = 'position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden;';
    document.body.appendChild(stageAnnouncement);
    
    // Update announcement when stage changes
    const originalSetCurrentStage = setCurrentStage;
    setCurrentStage = function(stageIndex) {
        originalSetCurrentStage(stageIndex);
        const stage = wheelStages[stageIndex];
        stageAnnouncement.textContent = `Now viewing stage ${stage.id}: ${stage.title}. ${stage.essence}`;
    };
}

// === FINAL INITIALIZATION ===
document.addEventListener('DOMContentLoaded', function() {
    // Small delay to ensure everything is loaded
    setTimeout(() => {
        addMysticalEffects();
        enhanceAccessibility();
    }, 500);
});

// === UTILITY FUNCTIONS ===
function getRandomBetween(min, max) {
    return Math.random() * (max - min) + min;
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// === EXPORT FOR POTENTIAL MODULE USE ===
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        wheelStages,
        setCurrentStage,
        nextStage,
        prevStage,
        toggleAutoPlay
    };
}
