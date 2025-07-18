const axios = require('axios');
const { FRIGATE, MQTT } = require('../constants')();
const frigateAuth = require('./frigate-auth.util');

const frigate = this;

module.exports.subLabel = async (topic, id, best) => {
  console.verbose(
    `FRIGATE.URL: ${FRIGATE.URL}; FRIGATE.UPDATE_SUB_LABELS: ${FRIGATE.UPDATE_SUB_LABELS}; best.length: ${best.length}`
  );
  if (!FRIGATE.URL || !FRIGATE.UPDATE_SUB_LABELS || !best.length) return;
  const names = best
    .map(({ name }) => name)
    .sort()
    .join(', ');
  const confidences = Math.max(...best.map(({ confidence }) => confidence)) / 100;
  if (confidences < 0 || confidences > 1) {
    throw new Error(
      `Confidences must be greater than 0 and smaller than 1, but now it's ${confidences}`
    );
  }

  const baseURL = this.topicURL(topic);
  const username = FRIGATE.USERNAME;
  const password = FRIGATE.PASSWORD;
  
  if (username && password) {
    // Use authenticated request
    await frigateAuth.authenticatedRequest({
      method: 'post',
      url: `${baseURL}/api/events/${id}/sub_label`,
      data: { subLabel: names, subLabelScore: confidences },
    }, baseURL, username, password).catch((error) =>
      console.error(`post sublabel to frigate for event ${id} error: ${error.message}`)
    );
  } else {
    // Use unauthenticated request (backward compatibility)
    await axios({
      method: 'post',
      url: `${baseURL}/api/events/${id}/sub_label`,
      data: { subLabel: names, subLabelScore: confidences },
    }).catch((error) =>
      console.error(`post sublabel to frigate for event ${id} error: ${error.message}`)
    );
  }
};

module.exports.checks = async ({
  id,
  frigateEventType: type,
  topic,
  label,
  camera,
  area,
  zones,
  PROCESSING,
  IDS,
}) => {
  try {
    if (!FRIGATE.URL) throw Error('Frigate URL not configured');

    const cameraMatch = FRIGATE.ZONES
      ? FRIGATE.ZONES.filter(({ CAMERA }) => camera === CAMERA).length
        ? FRIGATE.ZONES.filter(({ CAMERA }) => camera === CAMERA)[0]
        : false
      : false;

    if (FRIGATE.CAMERAS.length > 0 && !FRIGATE.CAMERAS.includes(camera) && !cameraMatch) {
      return `${id} - ${camera} not on approved list`;
    }

    if (FRIGATE.ZONES) {
      if (cameraMatch) {
        const [match] = FRIGATE.ZONES.filter(
          ({ CAMERA, ZONE }) => camera === CAMERA && zones.includes(ZONE)
        );

        if (!match) {
          return `${id} - ${camera} zone not on approved list`;
        }
      }
    }

    if (PROCESSING && type === 'update') {
      return `${id} - still processing previous request`;
    }

    if (type === 'end') {
      return `${id} - skip processing on ${type} events`;
    }

    if (!FRIGATE.LABELS.includes(label)) {
      return `${id} - ${label} label not in (${FRIGATE.LABELS.join(', ')})`;
    }

    if (FRIGATE.MIN_AREA > area) {
      return `skipping object area smaller than ${FRIGATE.MIN_AREA} (${area})`;
    }

    if (IDS.includes(id)) {
      return `already processed ${id}`;
    }

    await frigate.status(topic);

    return true;
  } catch (error) {
    throw new Error(error.message);
  }
};

module.exports.status = async (topic) => {
  try {
    const baseURL = this.topicURL(topic);
    const username = FRIGATE.USERNAME;
    const password = FRIGATE.PASSWORD;
    
    if (username && password) {
      // Use authenticated request
      const request = await frigateAuth.authenticatedRequest({
        method: 'get',
        url: `${baseURL}/api/version`,
        timeout: 5 * 1000,
      }, baseURL, username, password);
      return request.data;
    } else {
      // Use unauthenticated request (backward compatibility)
      const request = await axios({
        method: 'get',
        url: `${baseURL}/api/version`,
        timeout: 5 * 1000,
      });
      return request.data;
    }
  } catch (error) {
    throw new Error(`frigate status error: ${error.message}`);
  }
};

module.exports.topicURL = (topic) => {
  try {
    if (typeof FRIGATE.URL === 'string') return FRIGATE.URL;
    return FRIGATE.URL[MQTT.TOPICS.FRIGATE.indexOf(topic)];
  } catch (error) {
    error.message = `frigate topic url error: ${error.message}`;
    throw error;
  }
};
