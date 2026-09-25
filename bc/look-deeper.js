var heroTimeline = new TimelineMax({repeat: -1});

heroTimeline
  .staggerFrom('#Bubbles path, #Bubbles circle', 3, { cycle: {y: ["+=25","+8", "+0", "+0"], scale: ["0", ".98", ".9"], x: ["+=2", "+=0", "+=3"]}, ease: Power1.easeIn, yoyo: true, repeat: 1 }, 0.01)
  .staggerFromTo('#Clouds path', 3, { y: "+=3", x: "-=3", scale: '1.05' }, { y: "-=3", x: "+=2", scale: '.95', yoyo: true, repeat: 1 }, 0.1, 0)
  .staggerFromTo('#Fish path', 2, { x: "-2", scale: '0.95', rotateZ: "-3deg", rotateY: "-1deg" }, { x: "+=2", scale: '1.15', rotateZ: '3deg', rotateY: "+4deg", ease: Power1.easeIn, yoyo: true, repeat: 3 }, 0.1, 0);