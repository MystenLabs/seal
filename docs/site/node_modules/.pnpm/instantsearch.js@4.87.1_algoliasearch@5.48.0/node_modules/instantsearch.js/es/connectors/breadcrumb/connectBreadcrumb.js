function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
import { checkRendering, warning, createDocumentationMessageGenerator, isEqual, noop } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'breadcrumb',
  connector: true
});
var connectBreadcrumb = function connectBreadcrumb(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  var connectorState = {};
  return function (widgetParams) {
    var _ref = widgetParams || {},
      attributes = _ref.attributes,
      _ref$separator = _ref.separator,
      separator = _ref$separator === void 0 ? ' > ' : _ref$separator,
      _ref$rootPath = _ref.rootPath,
      rootPath = _ref$rootPath === void 0 ? null : _ref$rootPath,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (items) {
        return items;
      } : _ref$transformItems;
    if (!attributes || !Array.isArray(attributes) || attributes.length === 0) {
      throw new Error(withUsage('The `attributes` option expects an array of strings.'));
    }
    var _attributes = _slicedToArray(attributes, 1),
      hierarchicalFacetName = _attributes[0];
    function getRefinedState(state, facetValue) {
      if (!facetValue) {
        var breadcrumb = state.getHierarchicalFacetBreadcrumb(hierarchicalFacetName);
        if (breadcrumb.length === 0) {
          return state;
        } else {
          return state.resetPage().toggleFacetRefinement(hierarchicalFacetName, breadcrumb[0]);
        }
      }
      return state.resetPage().toggleFacetRefinement(hierarchicalFacetName, facetValue);
    }
    return {
      $$type: 'ais.breadcrumb',
      init: function init(initOptions) {
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: initOptions.instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(renderOptions)), {}, {
          instantSearchInstance: renderOptions.instantSearchInstance
        }), false);
      },
      dispose: function dispose() {
        unmountFn();
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          breadcrumb: _objectSpread(_objectSpread({}, renderState.breadcrumb), {}, _defineProperty({}, hierarchicalFacetName, this.getWidgetRenderState(renderOptions)))
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref2) {
        var _this = this;
        var helper = _ref2.helper,
          createURL = _ref2.createURL,
          results = _ref2.results,
          state = _ref2.state;
        function getItems() {
          // The hierarchicalFacets condition is required for flavors
          // that render immediately with empty results, without relying
          // on init() (like React InstantSearch).
          if (!results || state.hierarchicalFacets.length === 0) {
            return [];
          }
          var facetValues = results.getFacetValues(hierarchicalFacetName, {});
          var facetItems = facetValues && !Array.isArray(facetValues) && facetValues.data ? facetValues.data : [];
          var items = transformItems(shiftItemsValues(prepareItems(facetItems)), {
            results: results
          });
          return items;
        }
        var items = getItems();
        if (!connectorState.createURL) {
          connectorState.createURL = function (facetValue) {
            return createURL(function (uiState) {
              return _this.getWidgetUiState(uiState, {
                searchParameters: getRefinedState(helper.state, facetValue),
                helper: helper
              });
            });
          };
        }
        if (!connectorState.refine) {
          connectorState.refine = function (facetValue) {
            helper.setState(getRefinedState(helper.state, facetValue)).search();
          };
        }
        return {
          canRefine: items.length > 0,
          createURL: connectorState.createURL,
          items: items,
          refine: connectorState.refine,
          widgetParams: widgetParams
        };
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref3) {
        var searchParameters = _ref3.searchParameters;
        var path = searchParameters.getHierarchicalFacetBreadcrumb(hierarchicalFacetName);
        return removeEmptyRefinementsFromUiState(_objectSpread(_objectSpread({}, uiState), {}, {
          hierarchicalMenu: _objectSpread(_objectSpread({}, uiState.hierarchicalMenu), {}, _defineProperty({}, hierarchicalFacetName, path))
        }), hierarchicalFacetName);
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref4) {
        var uiState = _ref4.uiState;
        var values = uiState.hierarchicalMenu && uiState.hierarchicalMenu[hierarchicalFacetName];
        if (searchParameters.isConjunctiveFacet(hierarchicalFacetName) || searchParameters.isDisjunctiveFacet(hierarchicalFacetName)) {
          process.env.NODE_ENV === 'development' ? warning(false, "HierarchicalMenu: Attribute \"".concat(hierarchicalFacetName, "\" is already used by another widget applying conjunctive or disjunctive faceting.\nAs this is not supported, please make sure to remove this other widget or this HierarchicalMenu widget will not work at all.")) : void 0;
          return searchParameters;
        }
        if (searchParameters.isHierarchicalFacet(hierarchicalFacetName)) {
          var facet = searchParameters.getHierarchicalFacetByName(hierarchicalFacetName);
          process.env.NODE_ENV === 'development' ? warning(isEqual(facet.attributes, attributes) && facet.separator === separator && facet.rootPath === rootPath, 'Using Breadcrumb and HierarchicalMenu on the same facet with different options overrides the configuration of the HierarchicalMenu.') : void 0;
        }
        var withFacetConfiguration = searchParameters.removeHierarchicalFacet(hierarchicalFacetName).addHierarchicalFacet({
          name: hierarchicalFacetName,
          attributes: attributes,
          separator: separator,
          rootPath: rootPath
        });
        if (!values) {
          return withFacetConfiguration.setQueryParameters({
            hierarchicalFacetsRefinements: _objectSpread(_objectSpread({}, withFacetConfiguration.hierarchicalFacetsRefinements), {}, _defineProperty({}, hierarchicalFacetName, []))
          });
        }
        return withFacetConfiguration.addHierarchicalFacetRefinement(hierarchicalFacetName, values.join(separator));
      }
    };
  };
};
function prepareItems(data) {
  return data.reduce(function (result, currentItem) {
    if (currentItem.isRefined) {
      result.push({
        label: currentItem.name,
        value: currentItem.escapedValue
      });
      if (Array.isArray(currentItem.data)) {
        result = result.concat(prepareItems(currentItem.data));
      }
    }
    return result;
  }, []);
}
function shiftItemsValues(array) {
  return array.map(function (x, idx) {
    return {
      label: x.label,
      value: idx + 1 === array.length ? null : array[idx + 1].value
    };
  });
}
function removeEmptyRefinementsFromUiState(indexUiState, attribute) {
  if (!indexUiState.hierarchicalMenu) {
    return indexUiState;
  }
  if (!indexUiState.hierarchicalMenu[attribute] || !indexUiState.hierarchicalMenu[attribute].length) {
    delete indexUiState.hierarchicalMenu[attribute];
  }
  if (Object.keys(indexUiState.hierarchicalMenu).length === 0) {
    delete indexUiState.hierarchicalMenu;
  }
  return indexUiState;
}
export default connectBreadcrumb;