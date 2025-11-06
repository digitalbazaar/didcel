export function createJsonldPrettyPrinter({preferOrder}) {
  return (key, value) => {
    let result = value;
    if(value instanceof Object && !(value instanceof Array)) {
      let sortedKeys = Object.keys(value).sort();
      let prettyKeys = [];

      for(let pkey of preferOrder) {
        if(value[pkey] !== undefined) {
          prettyKeys.push(pkey);
        }
      }
      for(let skey of sortedKeys) {
        if(!preferOrder.includes(skey)) {
          prettyKeys.push(skey);
        }
      }

      result = prettyKeys.reduce((sorted, key) => {
        sorted[key] = value[key];
        return sorted;
      }, {});
    }

    return result;
  }
}

export default {createJsonldPrettyPrinter};
