// Barra de abas simples e controlada — sem estado interno, o pai decide
// qual aba está ativa (normalmente sincronizado com a URL via
// useSearchParams, pra dar link compartilhável/navegável).
export default function Tabs({ tabs, active, onChange }) {
  return (
    <div className="tab-bar" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={tab.id === active}
          className={`tab-bar__item${tab.id === active ? ' tab-bar__item--active' : ''}`}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  )
}
