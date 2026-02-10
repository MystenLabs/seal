function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _toConsumableArray(r) { return _arrayWithoutHoles(r) || _iterableToArray(r) || _unsupportedIterableToArray(r) || _nonIterableSpread(); }
function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _iterableToArray(r) { if ("undefined" != typeof Symbol && null != r[Symbol.iterator] || null != r["@@iterator"]) return Array.from(r); }
function _arrayWithoutHoles(r) { if (Array.isArray(r)) return _arrayLikeToArray(r); }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { getRefinements, checkRendering, createDocumentationMessageGenerator, noop, warning } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'current-refinements',
  connector: true
});
var connectCurrentRefinements = function connectCurrentRefinements(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    if ((widgetParams || {}).includedAttributes && (widgetParams || {}).excludedAttributes) {
      throw new Error(withUsage('The options `includedAttributes` and `excludedAttributes` cannot be used together.'));
    }
    var _ref = widgetParams || {},
      includedAttributes = _ref.includedAttributes,
      _ref$excludedAttribut = _ref.excludedAttributes,
      excludedAttributes = _ref$excludedAttribut === void 0 ? ['query'] : _ref$excludedAttribut,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (items) {
        return items;
      } : _ref$transformItems;
    return {
      $$type: 'ais.currentRefinements',
      init: function init(initOptions) {
        var instantSearchInstance = initOptions.instantSearchInstance;
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        var instantSearchInstance = renderOptions.instantSearchInstance;
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(renderOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), false);
      },
      dispose: function dispose() {
        unmountFn();
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          currentRefinements: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref2) {
        var results = _ref2.results,
          scopedResults = _ref2.scopedResults,
          _createURL = _ref2.createURL,
          helper = _ref2.helper;
        function getItems() {
          if (!results) {
            return transformItems(getRefinementsItems({
              results: null,
              helper: helper,
              indexId: helper.state.index,
              includedAttributes: includedAttributes,
              excludedAttributes: excludedAttributes
            }), {
              results: results
            });
          }
          return scopedResults.reduce(function (accResults, scopedResult) {
            return accResults.concat(transformItems(getRefinementsItems({
              results: scopedResult.results,
              helper: scopedResult.helper,
              indexId: scopedResult.indexId,
              includedAttributes: includedAttributes,
              excludedAttributes: excludedAttributes
            }), {
              results: results
            }));
          }, []);
        }
        var items = getItems();
        return {
          items: items,
          canRefine: items.length > 0,
          refine: function refine(refinement) {
            return clearRefinement(helper, refinement);
          },
          createURL: function createURL(refinement) {
            return _createURL(clearRefinementFromState(helper.state, refinement));
          },
          widgetParams: widgetParams
        };
      }
    };
  };
};
function getRefinementsItems(_ref3) {
  var results = _ref3.results,
    helper = _ref3.helper,
    indexId = _ref3.indexId,
    includedAttributes = _ref3.includedAttributes,
    excludedAttributes = _ref3.excludedAttributes;
  var includesQuery = (includedAttributes || []).indexOf('query') !== -1 || (excludedAttributes || []).indexOf('query') === -1;
  var filterFunction = includedAttributes ? function (item) {
    return includedAttributes.indexOf(item.attribute) !== -1;
  } : function (item) {
    return excludedAttributes.indexOf(item.attribute) === -1;
  };
  var items = getRefinements(results, helper.state, includesQuery).map(normalizeRefinement).filter(filterFunction);
  return items.reduce(function (allItems, currentItem) {
    return [].concat(_toConsumableArray(allItems.filter(function (item) {
      return item.attribute !== currentItem.attribute;
    })), [{
      indexName: helper.state.index,
      indexId: indexId,
      attribute: currentItem.attribute,
      label: currentItem.attribute,
      refinements: items.filter(function (result) {
        return result.attribute === currentItem.attribute;
      })
      // We want to keep the order of refinements except the numeric ones.
      .sort(function (a, b) {
        return a.type === 'numeric' ? a.value - b.value : 0;
      }),
      refine: function refine(refinement) {
        return clearRefinement(helper, refinement);
      }
    }]);
  }, []);
}
function clearRefinementFromState(state, refinement) {
  state = state.resetPage();
  switch (refinement.type) {
    case 'facet':
      return state.removeFacetRefinement(refinement.attribute, String(refinement.value));
    case 'disjunctive':
      return state.removeDisjunctiveFacetRefinement(refinement.attribute, String(refinement.value));
    case 'hierarchical':
      return state.removeHierarchicalFacetRefinement(refinement.attribute);
    case 'exclude':
      return state.removeExcludeRefinement(refinement.attribute, String(refinement.value));
    case 'numeric':
      return state.removeNumericRefinement(refinement.attribute, refinement.operator, String(refinement.value));
    case 'tag':
      return state.removeTagRefinement(String(refinement.value));
    case 'query':
      return state.setQueryParameter('query', '');
    default:
      process.env.NODE_ENV === 'development' ? warning(false, "The refinement type \"".concat(refinement.type, "\" does not exist and cannot be cleared from the current refinements.")) : void 0;
      return state;
  }
}
function clearRefinement(helper, refinement) {
  helper.setState(clearRefinementFromState(helper.state, refinement)).search();
}
function getOperatorSymbol(operator) {
  switch (operator) {
    case '>=':
      return '≥';
    case '<=':
      return '≤';
    default:
      return operator;
  }
}
function normalizeRefinement(refinement) {
  var value = getValue(refinement);
  var label = refinement.operator ? "".concat(getOperatorSymbol(refinement.operator), " ").concat(refinement.name) : refinement.name;
  var normalizedRefinement = {
    attribute: refinement.attribute,
    type: refinement.type,
    value: value,
    label: label
  };
  if (refinement.operator !== undefined) {
    normalizedRefinement.operator = refinement.operator;
  }
  if (refinement.count !== undefined) {
    normalizedRefinement.count = refinement.count;
  }
  if (refinement.exhaustive !== undefined) {
    normalizedRefinement.exhaustive = refinement.exhaustive;
  }
  return normalizedRefinement;
}
function getValue(refinement) {
  if (refinement.type === 'numeric') {
    return Number(refinement.name);
  }
  if ('escapedValue' in refinement) {
    return refinement.escapedValue;
  }
  return refinement.name;
}
export default connectCurrentRefinements;